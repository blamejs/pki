// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.asn1 (strict DER codec).
 * Oracle: X.690 hand-computed TLV vectors + adversarial non-DER inputs
 * the decoder must reject (indefinite length, non-minimal, trailing).
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var vectors = helpers.vectors;
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
function hex(buf) { return Buffer.from(buf).toString("hex"); }

function testBuildVectors() {
  var b = pki.asn1.build;
  var map = {
    "INTEGER 0":      b.integer(0n),
    "INTEGER 127":    b.integer(127n),
    "INTEGER 128":    b.integer(128n),
    "INTEGER 256":    b.integer(256n),
    "INTEGER -128":   b.integer(-128n),
    "BOOLEAN true":   b.boolean(true),
    "BOOLEAN false":  b.boolean(false),
    "NULL":           b.nullValue(),
    "SEQUENCE empty": b.sequence([]),
    "OID sha256":     b.oid("2.16.840.1.101.3.4.2.1"),
  };
  vectors.DER_TLV.forEach(function (t) {
    check("build " + t[0] + " -> " + t[1], hex(map[t[0]]) === t[1]);
  });
}

function testRoundTrip() {
  var b = pki.asn1.build;
  check("read.integer round-trips 128", pki.asn1.read.integer(pki.asn1.decode(b.integer(128n))) === 128n);
  check("read.integer round-trips large", (function () {
    var big = 123456789012345678901234567890n;
    return pki.asn1.read.integer(pki.asn1.decode(b.integer(big))) === big;
  })());
  check("read.boolean round-trips", pki.asn1.read.boolean(pki.asn1.decode(b.boolean(true))) === true);
  check("read.null round-trips", pki.asn1.read.nullValue(pki.asn1.decode(b.nullValue())) === null);
  check("read.octetString round-trips", pki.asn1.read.octetString(pki.asn1.decode(b.octetString(Buffer.from("hi")))).toString() === "hi");
  check("read.oid round-trips", pki.asn1.read.oid(pki.asn1.decode(b.oid("1.2.840.10045.2.1"))) === "1.2.840.10045.2.1");
  check("read.utf8 round-trips", pki.asn1.read.string(pki.asn1.decode(b.utf8("héllo"))) === "héllo");
  check("sequence nests + navigates", (function () {
    var der = b.sequence([b.integer(1n), b.oid("2.5.4.3"), b.utf8("x")]);
    var node = pki.asn1.decode(der);
    return node.tagNumber === pki.asn1.TAGS.SEQUENCE && node.children.length === 3 &&
      pki.asn1.read.oid(node.children[1]) === "2.5.4.3";
  })());
  check("time round-trips to the second", (function () {
    var d = new Date("2026-07-04T07:00:27.000Z");
    return pki.asn1.read.time(pki.asn1.decode(b.utcTime(d))).getTime() === d.getTime();
  })());
}

function testOidContent() {
  vectors.OID_CONTENT.forEach(function (t) {
    check("encodeOidContent " + t[0], hex(pki.asn1.encodeOidContent(t[0])) === t[1]);
    check("decodeOidContent " + t[1], pki.asn1.decodeOidContent(Buffer.from(t[1], "hex")) === t[0]);
  });
}

function testRejects() {
  // Indefinite length (BER, not DER): 30 80 ... 00 00.
  check("rejects indefinite length", code(function () { pki.asn1.decode(Buffer.from("30800000", "hex")); }) === "asn1/indefinite-length");
  // Non-minimal long-form length: 02 81 01 00 (should be 02 01 00).
  check("rejects non-minimal length", code(function () { pki.asn1.decode(Buffer.from("02810100", "hex")); }) === "asn1/non-minimal-length");
  // Non-minimal INTEGER: 02 02 00 01 (leading zero not needed).
  check("rejects non-minimal integer", code(function () { pki.asn1.read.integer(pki.asn1.decode(Buffer.from("02020001", "hex"))); }) === "asn1/non-minimal-integer");
  // Truncated: declares 5 content octets, buffer has 1.
  check("rejects truncated content", code(function () { pki.asn1.decode(Buffer.from("040501", "hex")); }) === "asn1/truncated");
  // Trailing bytes after the top-level value.
  check("rejects trailing bytes", code(function () { pki.asn1.decode(Buffer.from("050000", "hex")); }) === "asn1/trailing-bytes");
  // DER BOOLEAN must be 0x00 / 0xFF.
  check("rejects non-canonical boolean", code(function () { pki.asn1.read.boolean(pki.asn1.decode(Buffer.from("010101", "hex"))); }) === "asn1/bad-boolean");
  // Depth cap.
  check("enforces depth cap", code(function () {
    var d = pki.asn1.build.integer(1n);
    for (var i = 0; i < 5; i++) d = pki.asn1.build.sequence([d]);
    pki.asn1.decode(d, { maxDepth: 2 });
  }) === "asn1/too-deep");
  // Size cap.
  check("enforces size cap", code(function () { pki.asn1.decode(pki.asn1.build.octetString(Buffer.alloc(100)), { maxBytes: 10 }); }) === "asn1/too-large");
  // OID first-arc bound.
  check("rejects OID first arc > 2", code(function () { pki.asn1.encodeOidContent("3.1.1"); }) === "oid/bad-arc");
}

function testIntegerAndOidCaps() {
  var TAGS = pki.asn1.TAGS;
  // FIX 1 — quadratic-BigInt DoS: an over-cap INTEGER is refused before
  // the BigInt magnitude is built. DER_MAX_INTEGER_BYTES is 16384; any
  // longer content (a hostile length prefix) must be rejected up front.
  var bigIntDer = pki.asn1.encode(0x00, false, TAGS.INTEGER, Buffer.alloc(20000, 0x01));
  check("over-cap INTEGER throws integer-too-large",
    code(function () { pki.asn1.read.integer(pki.asn1.decode(bigIntDer)); }) === "asn1/integer-too-large");
  // A single OID sub-identifier whose continuation run blows the cap
  // (OID_MAX_SUBIDENTIFIER_BYTES is 16); 0x81 keeps the continuation bit
  // set, so this is one never-terminating sub-identifier.
  check("over-cap OID sub-identifier throws subidentifier-too-large",
    code(function () { pki.asn1.decodeOidContent(Buffer.alloc(64, 0x81)); }) === "oid/subidentifier-too-large");
  // In-cap values still round-trip (defense-in-depth must not reject valid DER).
  check("in-cap INTEGER round-trips", (function () {
    var big = 0n;
    for (var i = 0; i < 100; i++) big = (big << 8n) | 0x7Fn;
    return pki.asn1.read.integer(pki.asn1.decode(pki.asn1.build.integer(big))) === big;
  })());
  check("in-cap OID round-trips", pki.asn1.decodeOidContent(pki.asn1.encodeOidContent("2.16.840.1.101.3.4.2.1")) === "2.16.840.1.101.3.4.2.1");
  // A 128-bit UUID-based OID arc (X.667, e.g. 2.25.<uuid>) encodes as 19
  // base-128 bytes — the sub-identifier cap must admit it, not reject a
  // legitimate UUID OID as hostile.
  var uuidOid = "2.25.340282366920938463463374607431768211455"; // 2.25.(2^128 - 1)
  check("128-bit UUID OID arc round-trips",
    pki.asn1.read.oid(pki.asn1.decode(pki.asn1.build.oid(uuidOid))) === uuidOid);
}

function testTimeOutOfRange() {
  var TAGS = pki.asn1.TAGS;
  function readGen(s) { return pki.asn1.read.time(pki.asn1.decode(pki.asn1.encode(0x00, false, TAGS.GENERALIZED_TIME, Buffer.from(s, "latin1")))); }
  function readUtc(s) { return pki.asn1.read.time(pki.asn1.decode(pki.asn1.encode(0x00, false, TAGS.UTC_TIME, Buffer.from(s, "latin1")))); }
  // FIX 2 — Date.UTC silently rolls over; every component must round-trip.
  ["20250230000000Z", "20251301000000Z", "20250101250000Z", "20250100000000Z"].forEach(function (s) {
    check("GeneralizedTime " + s + " throws bad-time", code(function () { readGen(s); }) === "asn1/bad-time");
  });
  ["250230000000Z", "250101250000Z"].forEach(function (s) {
    check("UTCTime " + s + " throws bad-time", code(function () { readUtc(s); }) === "asn1/bad-time");
  });
  // A valid time still parses.
  check("valid GeneralizedTime parses", readGen("20260704070027Z").getTime() === Date.UTC(2026, 6, 4, 7, 0, 27));
  check("valid UTCTime parses", readUtc("260704070027Z").getTime() === Date.UTC(2026, 6, 4, 7, 0, 27));
  // A GeneralizedTime year below 100 keeps its literal century — the
  // Date.UTC()/new Date() constructors remap 0..99 to 1900..1999, which
  // would corrupt "0099" to 1999. setUTCFullYear takes the year literally.
  check("GeneralizedTime year 0099 stays year 99", readGen("00990704000000Z").getUTCFullYear() === 99);
  check("GeneralizedTime year 0050 stays year 50", readGen("00500101000000Z").getUTCFullYear() === 50);
}

function testBitStringUnusedBits() {
  var TAGS = pki.asn1.TAGS;
  // FIX 3 — DER requires the declared unused low bits to be zero.
  var der = pki.asn1.encode(0x00, false, TAGS.BIT_STRING, Buffer.from([0x03, 0xFF]));
  check("BIT STRING with non-zero unused bits throws bad-bit-string",
    code(function () { pki.asn1.read.bitString(pki.asn1.decode(der)); }) === "asn1/bad-bit-string");
  // Canonical body still decodes (0xF8 = low 3 bits zero).
  var ok = pki.asn1.encode(0x00, false, TAGS.BIT_STRING, Buffer.from([0x03, 0xF8]));
  check("BIT STRING with zero unused bits decodes", pki.asn1.read.bitString(pki.asn1.decode(ok)).unusedBits === 3);
  // build.bitString rejects a caller tail whose unused bits are non-zero.
  check("build.bitString rejects non-zero unused tail",
    code(function () { pki.asn1.build.bitString(Buffer.from([0xFF]), 3); }) === "asn1/bad-bit-string");
  check("build.bitString accepts a canonical tail",
    code(function () { pki.asn1.build.bitString(Buffer.from([0xF8]), 3); }) === "NO-THROW");
}

function testUniversalStringScalarRange() {
  var TAGS = pki.asn1.TAGS;
  // FIX 4 — scalar value out of range must be a typed Asn1Error, not a bare RangeError.
  var der = pki.asn1.encode(0x00, false, TAGS.UNIVERSAL_STRING, Buffer.from([0xFF, 0x00, 0x00, 0x00]));
  check("UniversalString code point out of range throws bad-universal-string",
    code(function () { pki.asn1.read.string(pki.asn1.decode(der)); }) === "asn1/bad-universal-string");
  // Lone surrogate in UniversalString.
  var sur = pki.asn1.encode(0x00, false, TAGS.UNIVERSAL_STRING, Buffer.from([0x00, 0x00, 0xD8, 0x00]));
  check("UniversalString lone surrogate throws bad-universal-string",
    code(function () { pki.asn1.read.string(pki.asn1.decode(sur)); }) === "asn1/bad-universal-string");
  // Lone surrogate in BMPString.
  var bmp = pki.asn1.encode(0x00, false, TAGS.BMP_STRING, Buffer.from([0xD8, 0x00]));
  check("BMPString lone surrogate throws bad-bmp-string",
    code(function () { pki.asn1.read.string(pki.asn1.decode(bmp)); }) === "asn1/bad-bmp-string");
  // A valid UniversalString still decodes.
  var good = pki.asn1.encode(0x00, false, TAGS.UNIVERSAL_STRING, Buffer.from([0x00, 0x00, 0x00, 0x41]));
  check("valid UniversalString decodes", pki.asn1.read.string(pki.asn1.decode(good)) === "A");
}

function run() {
  testBuildVectors();
  testRoundTrip();
  testOidContent();
  testRejects();
  testIntegerAndOidCaps();
  testTimeOutOfRange();
  testBitStringUnusedBits();
  testUniversalStringScalarRange();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
