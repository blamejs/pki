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
var C = require("../../lib/constants.js");

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
  // RFC 2046 sec. 5.1.1: a delimiter must begin a line and be a complete token -- a "--boundary"
  // appearing MID-LINE in a part's content, or a longer "--boundaryextra", is NOT a delimiter.
  var midline = mime.splitMultipart(Buffer.from("--B\r\nfirst with --B inside a line\r\n--B\r\nsecond\r\n--B--\r\n"), "B", E, "m/bad");
  check("22. a mid-line --boundary is not a delimiter (content preserved)", midline.length === 2 && midline[0].toString() === "first with --B inside a line");
  check("23. a longer --boundaryextra token is not the boundary", mime.splitMultipart(Buffer.from("--B\r\ncontent\r\n--Bextra x\r\n--B--\r\n"), "B", E, "m/bad").length === 1);
  // a "--boundary" line with a NON-padding suffix is content, not a delimiter (only LWSP may follow).
  check("24. a --boundary line with a non-whitespace suffix is content", mime.splitMultipart(Buffer.from("--B\r\ncontent --B garbage\r\nmore\r\n--B\r\nsecond\r\n--B--\r\n"), "B", E, "m/bad")[0].toString().indexOf("--B garbage") >= 0);
  // trailing linear whitespace (transport padding) on a genuine delimiter line IS accepted.
  var padded = mime.splitMultipart(Buffer.from("--B \t\r\nfirst\r\n--B--\r\n"), "B", E, "m/bad");
  check("25. trailing LWSP transport-padding on a delimiter is accepted", padded.length === 1 && padded[0].toString() === "first");

  // ---- buildEntity: serialize fields + body, route each field through the header-injection guard, canonicalize ----
  var built = mime.buildEntity([{ name: "Content-Type", value: "text/plain" }, { name: "Subject", value: "Hi" }], Buffer.from("body\n"), E, "m/bad");
  var pb = mime.parse(built, E, "m/bad");
  check("26. buildEntity emits parseable headers + a CRLF-canonical body", pb.header("Subject") === "Hi" && pb.body.toString() === "body\r\n");
  check("27. buildEntity with a null body emits an empty body", mime.parse(mime.buildEntity([{ name: "X-A", value: "1" }], null, E, "m/bad"), E, "m/bad").body.length === 0);
  check("28. buildEntity routes a value through the header guard (CR/LF injection reject)", fault(function () { mime.buildEntity([{ name: "Subject", value: "a\r\nBcc: x" }], Buffer.alloc(0), E, "m/bad"); }) === "m/bad");
  check("29. buildEntity rejects a bad field name", fault(function () { mime.buildEntity([{ name: "Bad Name", value: "v" }], Buffer.alloc(0), E, "m/bad"); }) === "m/bad");
  // buildEntity serializes the guard-VALIDATED value, never a second (possibly stateful) coercion of the input.
  var n = 0, stateful = { toString: function () { n++; return n === 1 ? "safe" : "safe\r\nBcc: injected"; } };
  var stBuilt = mime.buildEntity([{ name: "X-H", value: stateful }], Buffer.alloc(0), E, "m/bad");
  check("30. buildEntity serializes the guard-validated value (no stateful-toString re-injection)", mime.parse(stBuilt, E, "m/bad").header("Bcc") === null && mime.parse(stBuilt, E, "m/bad").header("X-H") === "safe");
  // paramCount honors RFC 2045 quoted-pair escaping: a backslash-escaped quote inside a value does not end it.
  check("31. paramCount honors quoted-pair escapes", mime.paramCount("text/plain; charset=\"a\\\"; hp=fake\"", "hp") === 0);
  check("31. paramCount counts a real repeated parameter", mime.paramCount("text/plain; hp=\"x\"; hp=\"y\"", "hp") === 2);
  // RFC 5322 sec. 2.1.1: an emitted field line over 998 octets is rejected (a relay could re-fold it, changing signed bytes).
  check("32. buildEntity rejects an over-998-octet field line", fault(function () { mime.buildEntity([{ name: "Subject", value: new Array(1000).join("x") }], Buffer.alloc(0), E, "m/bad"); }) === "m/bad");
  var atLimit = new Array(990).join("x"); // "Subject" (7) + ": " (2) + 989 = 998 octets exactly
  check("33. buildEntity accepts a field line at the 998-octet limit", mime.parse(mime.buildEntity([{ name: "Subject", value: atLimit }], Buffer.alloc(0), E, "m/bad"), E, "m/bad").header("Subject") === atLimit);
  // RFC 5322 comments: a `;` / `=` inside a `(...)` comment is CFWS, not a structural parameter separator.
  check("34. paramCount ignores an hp= inside a MIME comment", mime.paramCount("text/plain; charset=us-ascii (note; hp=fake)", "hp") === 0 && mime.paramCount("text/plain; hp=x (c)", "hp") === 1);
  check("35. a MIME comment with a ; does not create a spurious parameter", Object.keys(mime.parse(Buffer.from("Content-Type: text/plain; charset=us-ascii (a; b=c)\r\n\r\nx"), E, "m/bad").contentType.params).length === 1);
  // RFC 5322 CFWS: a comment BETWEEN parameter tokens is whitespace -- it is not part of the parameter name or value.
  check("36. paramCount ignores a comment before the parameter name", mime.paramCount("text/plain; (note) hp=\"clear\"", "hp") === 1);
  check("37. a comment around a parameter is stripped from its name and value", (function () { var p = mime.parse(Buffer.from("Content-Type: text/plain; (c) charset=utf-8 (d)\r\n\r\nx"), E, "m/bad").contentType.params; return p.charset === "utf-8"; })());
  // a quoted-pair inside a comment is consumed: an escaped ')' does not close the comment early (both bytes dropped).
  check("38. a quoted-pair inside a comment does not close it early", mime.parse(Buffer.from("Content-Type: text/plain; hp=x (a\\)b)\r\n\r\nz"), E, "m/bad").contentType.params.hp === "x");
  // hasParam names a parameter with OR without a value (a bare "; hp" still names hp); comment-aware, media type ignored.
  check("39. hasParam detects a parameter with or without a value", mime.hasParam("text/plain; hp", "hp") === true && mime.hasParam("text/plain; hp=\"clear\"", "hp") === true && mime.hasParam("text/plain; charset=utf-8", "hp") === false);
  check("40. hasParam ignores a bare attribute inside a comment", mime.hasParam("text/plain; charset=x (hp)", "hp") === false);
  // paramNameCount counts bare AND valued occurrences of an attribute name (paramCount counts only valued).
  check("41. paramNameCount counts bare and valued attribute occurrences", mime.paramNameCount("text/plain; hp; hp=\"clear\"", "hp") === 2 && mime.paramNameCount("text/plain; charset=utf-8", "hp") === 0);

  /* A Content-Type that names one parameter TWICE has no value the parser can resolve: reading the
     last occurrence and reading the first are both conforming (RFC 2045 sec. 5.1 gives a parameter
     one occurrence) and they disagree, so two implementations handed the same bytes read the entity
     differently. The repeat is refused where the parameter record is built, which covers every name
     at once: `boundary` decides which octets a signature is checked over, `protocol` and
     `smime-type` decide whether the entity is accepted, `micalg` decides the digest reported back. */
  function dupEntity(ct) {
    return Buffer.from("Content-Type: " + ct + "\r\n\r\n" +
      "--REAL\r\nContent-Type: text/plain\r\n\r\nbody\r\n--REAL--\r\n", "latin1");
  }
  var repeated = [
    "multipart/mixed; boundary=\"DECOY\"; boundary=\"REAL\"",
    "multipart/mixed; boundary=\"REAL\"; boundary=\"DECOY\"",
    "multipart/signed; boundary=\"REAL\"; protocol=\"application/evil\"; protocol=\"application/pkcs7-signature\"",
    "multipart/signed; boundary=\"REAL\"; micalg=sha-256; micalg=md5",
    "application/pkcs7-mime; smime-type=enveloped-data; smime-type=signed-data",
    "text/plain; charset=us-ascii; charset=utf-8",
    "text/plain; hp; hp=\"clear\"",
    "text/plain; CHARSET=us-ascii; charset=utf-8",
  ];
  var refusedEvery = true, acceptedShape = null;
  for (var r = 0; r < repeated.length; r++) {
    if (fault(function () { mime.parse(dupEntity(repeated[r]), E, "mime/bad-entity"); }) !== "mime/bad-entity") {
      refusedEvery = false; acceptedShape = repeated[r];
    }
  }
  check("42. a repeated parameter of any name is refused, in either order and whatever its case" +
    (acceptedShape === null ? "" : " [accepted " + JSON.stringify(acceptedShape) + "]"), refusedEvery);
  // CONTROL: one occurrence of each parses, so the arm above is not refusing every entity it reads.
  var single = Buffer.from(
    "Content-Type: multipart/mixed; boundary=\"REAL\"; charset=utf-8\r\n\r\n" +
    "--REAL\r\nContent-Type: text/plain\r\n\r\nbody\r\n--REAL--\r\n", "latin1");
  check("42a. CONTROL one occurrence of each parameter still parses and splits",
    mime.parse(single, E, "mime/bad-entity").contentType.params.boundary === "REAL" &&
    mime.parse(single, E, "mime/bad-entity").contentType.params.charset === "utf-8" &&
    mime.splitMultipart(mime.parse(single, E, "mime/bad-entity").body, "REAL", E, "mime/bad-entity").length === 1);
  // CONTROL: a single BARE attribute is not a repeat, and still reaches the reader that owns it.
  check("42b. CONTROL a single bare attribute still parses, with no value recorded",
    mime.parse(Buffer.from("Content-Type: text/plain; hp\r\n\r\nx", "latin1"), E, "mime/bad-entity")
      .contentType.params.hp === undefined);
  // A repeated name inside a comment is not an occurrence: comments are stripped before counting.
  check("42c. a parameter name repeated only inside a comment is not a repeat",
    mime.parse(Buffer.from("Content-Type: text/plain; charset=utf-8 (charset=us-ascii)\r\n\r\nx", "latin1"),
      E, "mime/bad-entity").contentType.params.charset === "utf-8");
  // `__proto__` as a parameter name is counted on a null-prototype record, so it cannot read as seen.
  check("42d. a parameter named __proto__ is counted, not inherited",
    mime.parse(Buffer.from("Content-Type: text/plain; __proto__=x\r\n\r\ny", "latin1"), E, "mime/bad-entity")
      .contentType.params.__proto__ === "x" &&
    fault(function () {
      mime.parse(Buffer.from("Content-Type: text/plain; __proto__=x; __proto__=y\r\n\r\nz", "latin1"), E, "mime/bad-entity");
    }) === "mime/bad-entity");

  /* The same ambiguity one level up: a field that occurs twice. Resolving it means choosing an
     occurrence, and reading the first and reading the last are both conforming, so the media type a
     body is dispatched on would follow the order the two fields happen to appear in. Measured before
     the rule: the same two Content-Type fields swapped parsed as "text/plain" one way and
     "application/pkcs7-mime" the other. A field that may legally repeat stays readable from the
     `headers` array, which is where a consumer takes every occurrence. */
  var twoCt = Buffer.from("Content-Type: text/plain\r\nContent-Type: application/pkcs7-mime\r\n\r\nbody\r\n", "latin1");
  var twoCtSwapped = Buffer.from("Content-Type: application/pkcs7-mime\r\nContent-Type: text/plain\r\n\r\nbody\r\n", "latin1");
  var twoCtFolded = Buffer.from("Content-Type:\r\n text/plain\r\nContent-Type:\r\n text/html\r\n\r\nbody\r\n", "latin1");
  var twoCtCased = Buffer.from("content-type: text/plain\r\nCONTENT-TYPE: text/html\r\n\r\nbody\r\n", "latin1");
  check("43. an entity declaring Content-Type twice is refused, in either order, folded or re-cased",
    fault(function () { mime.parse(twoCt, E, "mime/bad-entity"); }) === "mime/bad-entity" &&
    fault(function () { mime.parse(twoCtSwapped, E, "mime/bad-entity"); }) === "mime/bad-entity" &&
    fault(function () { mime.parse(twoCtFolded, E, "mime/bad-entity"); }) === "mime/bad-entity" &&
    fault(function () { mime.parse(twoCtCased, E, "mime/bad-entity"); }) === "mime/bad-entity");
  check("43a. a repeated Content-Transfer-Encoding is refused too, not resolved by position",
    fault(function () {
      mime.parse(Buffer.from("Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n" +
        "Content-Transfer-Encoding: 7bit\r\n\r\nbody\r\n", "latin1"), E, "mime/bad-entity");
    }) === "mime/bad-entity");
  // CONTROL: a field that may legally repeat does not stop the entity parsing, and every occurrence
  // is retained; only resolving one of them to a single value is refused.
  var repeatable = mime.parse(Buffer.from(
    "Received: from a\r\nReceived: from b\r\nContent-Type: text/plain\r\n\r\nbody\r\n", "latin1"), E, "mime/bad-entity");
  check("43b. CONTROL a legally-repeated field parses and keeps every occurrence in headers",
    repeatable.contentType.type === "text/plain" &&
    repeatable.headers.filter(function (h) { return h.lname === "received"; }).length === 2);
  check("43c. resolving that repeated field to one value is refused",
    fault(function () { repeatable.header("Received"); }) === "mime/bad-entity" &&
    repeatable.header("Content-Type") === "text/plain");
  // CONTROL: a distinct field whose name merely contains another's is not an occurrence of it.
  check("43d. CONTROL a prefixed field name is not an occurrence of the field it contains",
    mime.parse(Buffer.from("Content-Type: text/plain\r\nX-Content-Type: text/html\r\n\r\nx", "latin1"),
      E, "mime/bad-entity").contentType.type === "text/plain");

  /* A parsed record must not read back the caller's later writes. Measured before the rule, on the
     shipped verb: `pki.smime.verify` returned `valid: true` and its `content` shared the caller's
     ArrayBuffer, so a write into that buffer after the verdict changed the bytes the caller read as
     verified. The record is taken into a store of its own, so what it reads back is the entity the
     verdict was computed over. */
  var held = Buffer.from("Content-Type: text/plain\r\n\r\nSECRET", "latin1");
  var snap = mime.parse(held, E, "mime/bad-entity");
  var snapBefore = snap.bodyBytes.toString("latin1");
  held[held.length - 1] = 0x58;
  check("44. a parsed record does not share the caller's buffer",
    snap.bodyBytes.buffer !== held.buffer && snap.bytes.buffer !== held.buffer &&
    snap.headerBytes.buffer !== held.buffer);
  check("44a. a caller writing into its own buffer after the parse does not change the record",
    snap.bodyBytes.toString("latin1") === snapBefore && snapBefore === "SECRET");
  // CONTROL: the snapshot is byte-identical, so the bytes a verifier hashes are unchanged by the copy.
  check("44b. CONTROL the snapshot is byte-for-byte the input it was taken from",
    mime.parse(Buffer.from("Content-Type: text/plain\r\n\r\nSECRET", "latin1"), E, "mime/bad-entity")
      .bytes.equals(Buffer.from("Content-Type: text/plain\r\n\r\nSECRET", "latin1")));
  // And the parts a detached signature is checked over are views of the snapshot, not of the caller.
  var heldMp = Buffer.from("Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\n\r\npart one\r\n--B--\r\n", "latin1");
  var mpRec = mime.parse(heldMp, E, "mime/bad-entity");
  check("44c. a split part does not share the caller's buffer either",
    mime.splitMultipart(mpRec.body, "B", E, "mime/bad-entity")[0].buffer !== heldMp.buffer);

  /* Counting work before doing it (CWE-834, CWE-770). Measured before the caps: a 1367 KiB body of
     200,000 empty parts split into 200,000 parts in 49 ms, 100,000 header lines parsed, and a
     Content-Type carrying 100,000 parameters built a 100,000-entry record. Each is now bounded by a
     C.LIMITS row. */
  // `new Array(n + 1).join(s)` is n copies of s, so this is the FIRST count the cap refuses.
  var manyParts = Buffer.from("Content-Type: multipart/mixed; boundary=B\r\n\r\n" +
    new Array(C.LIMITS.MIME_MAX_PARTS + 2).join("--B\r\n\r\n") + "--B--\r\n", "latin1");
  check("45. a part count one over MIME_MAX_PARTS is refused",
    fault(function () {
      mime.splitMultipart(mime.parse(manyParts, E, "mime/bad-entity").body, "B", E, "mime/bad-entity");
    }) === "mime/bad-entity");
  // CONTROL: a body at the cap still splits, so the arm above is a bound and not a blanket refusal.
  var atPartCap = Buffer.from("Content-Type: multipart/mixed; boundary=B\r\n\r\n" +
    new Array(C.LIMITS.MIME_MAX_PARTS + 1).join("--B\r\n\r\n") + "--B--\r\n", "latin1");
  check("45a. CONTROL a part count AT the cap still splits",
    mime.splitMultipart(mime.parse(atPartCap, E, "mime/bad-entity").body, "B", E, "mime/bad-entity")
      .length === C.LIMITS.MIME_MAX_PARTS);

  var manyHeaders = "";
  for (var mh = 0; mh < C.LIMITS.MIME_MAX_HEADERS + 1; mh++) manyHeaders += "X-H-" + mh + ": v\r\n";
  check("46. a header count over MIME_MAX_HEADERS is refused",
    fault(function () { mime.parse(Buffer.from(manyHeaders + "\r\nbody", "latin1"), E, "mime/bad-entity"); }) === "mime/bad-entity");
  var atHeaderCap = "";
  for (var ah = 0; ah < C.LIMITS.MIME_MAX_HEADERS; ah++) atHeaderCap += "X-H-" + ah + ": v\r\n";
  check("46a. CONTROL a header count AT the cap still parses",
    mime.parse(Buffer.from(atHeaderCap + "\r\nbody", "latin1"), E, "mime/bad-entity").headers.length === C.LIMITS.MIME_MAX_HEADERS);

  var manyParams = "text/plain";
  for (var pi = 0; pi < C.LIMITS.MIME_MAX_PARAMS + 1; pi++) manyParams += "; p" + pi + "=v";
  check("47. a parameter count over MIME_MAX_PARAMS is refused",
    fault(function () { mime.parse(Buffer.from("Content-Type: " + manyParams + "\r\n\r\nx", "latin1"), E, "mime/bad-entity"); }) === "mime/bad-entity");
  var atParamCap = "text/plain";
  for (var ap = 0; ap < C.LIMITS.MIME_MAX_PARAMS; ap++) atParamCap += "; p" + ap + "=v";
  check("47a. CONTROL a parameter count AT the cap still parses",
    Object.keys(mime.parse(Buffer.from("Content-Type: " + atParamCap + "\r\n\r\nx", "latin1"), E, "mime/bad-entity")
      .contentType.params).length === C.LIMITS.MIME_MAX_PARAMS);

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
