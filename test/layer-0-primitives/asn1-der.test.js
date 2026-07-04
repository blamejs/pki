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
  // A positive INTEGER at the magnitude cap with its top bit set carries a
  // leading 0x00 DER sign octet, so its content is cap+1 bytes — that must
  // parse (an RSA-131072 modulus is exactly this shape), while cap+2 is over.
  var cap = pki.C.LIMITS.DER_MAX_INTEGER_BYTES;
  var signPad = Buffer.concat([Buffer.from([0x00, 0x80]), Buffer.alloc(cap - 1, 0xAB)]); // cap+1 content bytes
  check("INTEGER at magnitude cap + DER sign pad parses",
    code(function () { pki.asn1.read.integer(pki.asn1.decode(pki.asn1.encode(0x00, false, TAGS.INTEGER, signPad))); }) === "NO-THROW");
  var overPad = Buffer.concat([Buffer.from([0x00, 0x80]), Buffer.alloc(cap, 0xAB)]); // cap+2 content bytes
  check("INTEGER beyond cap + sign pad is rejected",
    code(function () { pki.asn1.read.integer(pki.asn1.decode(pki.asn1.encode(0x00, false, TAGS.INTEGER, overPad))); }) === "asn1/integer-too-large");
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
  // X.690 8.6.2.3 — an empty BIT STRING has no content octets, so it must
  // declare zero unused bits; the encoder must not emit unused bits over nothing.
  check("build.bitString rejects empty body with unused bits",
    code(function () { pki.asn1.build.bitString(Buffer.alloc(0), 3); }) === "asn1/bad-bit-string");
  check("build.bitString accepts empty body with zero unused bits",
    code(function () { pki.asn1.build.bitString(Buffer.alloc(0), 0); }) === "NO-THROW");
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

function testUtcTimeYearRange() {
  var b = pki.asn1.build;
  // FIX A — RFC 5280 §4.1.2.5.1 restricts UTCTime to 1950..2049; a year
  // outside that wraps to the wrong century (2050 -> "50" -> decodes 1950).
  check("build.utcTime year 2050 throws bad-utctime",
    code(function () { b.utcTime(new Date(Date.UTC(2050, 0, 1))); }) === "asn1/bad-utctime");
  check("build.utcTime year 1949 throws bad-utctime",
    code(function () { b.utcTime(new Date(Date.UTC(1949, 11, 31))); }) === "asn1/bad-utctime");
  // A 2026 date still round-trips through UTCTime.
  check("build.utcTime year 2026 round-trips", (function () {
    var d = new Date(Date.UTC(2026, 6, 4, 7, 0, 27));
    return pki.asn1.read.time(pki.asn1.decode(b.utcTime(d))).getTime() === d.getTime();
  })());
}

function testGeneralizedTimeYearPad() {
  var b = pki.asn1.build;
  // FIX B — a GeneralizedTime year below 1000 must zero-pad to 4 digits, or
  // it emits 12-14 char content that read.time rejects.
  check("build.generalizedTime year 99 round-trips to 99", (function () {
    var d = new Date(0); d.setUTCFullYear(99, 0, 1); d.setUTCHours(0, 0, 0, 0);
    var got;
    try { got = pki.asn1.read.time(pki.asn1.decode(b.generalizedTime(d))).getUTCFullYear(); }
    catch (_e) { return false; }
    return got === 99;
  })());
  check("build.generalizedTime year 99 emits a 4-digit year", (function () {
    var d = new Date(0); d.setUTCFullYear(99, 0, 1); d.setUTCHours(0, 0, 0, 0);
    return pki.asn1.decode(b.generalizedTime(d)).content.toString("latin1") === "00990101000000Z";
  })());
  check("build.generalizedTime year 10000 throws bad-generalizedtime", (function () {
    var d = new Date(0); d.setUTCFullYear(10000, 0, 1); d.setUTCHours(0, 0, 0, 0);
    return code(function () { b.generalizedTime(d); }) === "asn1/bad-generalizedtime";
  })());
}

function testSequenceSetMustBeConstructed() {
  // FIX C — X.690 8.9.1/8.11.1: universal SEQUENCE (0x10) / SET (0x11) MUST be
  // constructed; a primitive-tagged one decodes to a leaf (children=null) that
  // constructed-structure consumers dereference as a parent.
  check("primitive-tagged SEQUENCE throws bad-tlv",
    code(function () { pki.asn1.decode(Buffer.from([0x10, 0x00])); }) === "asn1/bad-tlv");
  check("primitive-tagged SET throws bad-tlv",
    code(function () { pki.asn1.decode(Buffer.from([0x11, 0x00])); }) === "asn1/bad-tlv");
  // A normal constructed SEQUENCE still decodes.
  check("constructed SEQUENCE still decodes", (function () {
    var node = pki.asn1.decode(pki.asn1.build.sequence([pki.asn1.build.integer(1n)]));
    return node.tagNumber === pki.asn1.TAGS.SEQUENCE && node.constructed && node.children.length === 1;
  })());
}

function testIa5SevenBit() {
  var b = pki.asn1.build;
  // FIX D — IA5String is 7-bit (0..127); a byte > 0x7F is not IA5.
  check("build.ia5 rejects a byte > 0x7F",
    code(function () { b.ia5(String.fromCharCode(0xE9)); }) === "asn1/bad-ia5-string");
  check("build.ia5 accepts plain ASCII", code(function () { b.ia5("abc"); }) === "NO-THROW");
  // A code point > 0xFF that latin1 truncates to a low ASCII byte (U+0141 ->
  // 0x41) must be rejected on the INPUT, not slip past a post-conversion check.
  check("build.ia5 rejects a truncation-prone code point (U+0141)",
    code(function () { b.ia5(String.fromCharCode(0x141)); }) === "asn1/bad-ia5-string");
}

function testSetSorted() {
  var b = pki.asn1.build;
  // FIX E — DER (X.690 11.6) requires SET components in ascending encoded
  // order, regardless of caller order.
  var tlvA = b.integer(1n); // 02 01 01
  var tlvB = b.integer(2n); // 02 01 02  (tlvA < tlvB by Buffer.compare)
  check("build.set sorts components canonically",
    hex(b.set([tlvB, tlvA])) === hex(b.set([tlvA, tlvB])));
}

function testIntegerBufferMinimal() {
  var b = pki.asn1.build;
  // FIX F — a raw INTEGER/ENUMERATED Buffer must be non-empty + minimal, or
  // build emits content read.integer rejects.
  check("build.integer rejects a non-minimal positive buffer",
    code(function () { b.integer(Buffer.from([0x00, 0x01])); }) === "asn1/non-minimal-integer");
  check("build.integer rejects a non-minimal negative buffer",
    code(function () { b.integer(Buffer.from([0xff, 0x80])); }) === "asn1/non-minimal-integer");
  check("build.integer rejects an empty buffer",
    code(function () { b.integer(Buffer.alloc(0)); }) === "asn1/bad-integer");
  // Symmetric with read.integer's per-value ceiling: a builder must not emit
  // an over-cap INTEGER (DER_MAX_INTEGER_BYTES + 1 for the sign octet).
  check("build.integer rejects an over-cap buffer",
    code(function () { b.integer(Buffer.alloc(20000, 0x01)); }) === "asn1/integer-too-large");
  check("build.integer rejects an over-cap BigInt",
    code(function () { b.integer(2n ** (8n * 17000n)); }) === "asn1/integer-too-large");
  check("build.enumerated rejects a non-minimal buffer",
    code(function () { b.enumerated(Buffer.from([0x00, 0x01])); }) === "asn1/non-minimal-integer");
  check("build.integer still accepts a BigInt", code(function () { b.integer(5n); }) === "NO-THROW");
  check("build.integer accepts a minimal positive buffer with a sign octet",
    code(function () { b.integer(Buffer.from([0x00, 0x80])); }) === "NO-THROW");
  // A minimal buffer round-trips through read.integer.
  check("build.integer buffer round-trips", (function () {
    return pki.asn1.read.integer(pki.asn1.decode(b.integer(Buffer.from([0x00, 0x80])))) === 128n;
  })());
}

function testOidSubIdentifierCap() {
  var b = pki.asn1.build;
  // FIX G — build.oid can't emit a sub-identifier over the byte cap the
  // decoder rejects (OID_MAX_SUBIDENTIFIER_BYTES).
  check("build.oid rejects an over-cap sub-identifier",
    code(function () { b.oid("2.25." + (2n ** 260n).toString()); }) === "oid/subidentifier-too-large");
  check("build.oid accepts a normal OID",
    code(function () { b.oid("2.16.840.1.101.3.4.2.1"); }) === "NO-THROW");
  // A 128-bit UUID arc (X.667 2.25.<uuid>) is 19 base-128 bytes — under the
  // cap, so it must still encode and round-trip.
  var uuidOid = "2.25.340282366920938463463374607431768211455";
  check("build.oid accepts a 128-bit UUID arc",
    pki.asn1.read.oid(pki.asn1.decode(b.oid(uuidOid))) === uuidOid);
}

function testReadStringValidation() {
  var TAGS = pki.asn1.TAGS;
  function decRead(tag, bytes) {
    return pki.asn1.read.string(pki.asn1.decode(pki.asn1.encode(0x00, false, tag, Buffer.from(bytes))));
  }
  // FIX H — IA5String content bytes >= 0x80 are not 7-bit ASCII.
  check("read IA5String with a 0x80 byte throws bad-ia5-string",
    code(function () { decRead(TAGS.IA5_STRING, [0x41, 0x80]); }) === "asn1/bad-ia5-string");
  check("read a valid IA5String decodes", decRead(TAGS.IA5_STRING, [0x61, 0x62, 0x63]) === "abc");
  // FIX I — PrintableString outside the restricted set (here "@").
  check("read PrintableString with '@' throws bad-printable-string",
    code(function () { decRead(TAGS.PRINTABLE_STRING, Buffer.from("A@B", "latin1")); }) === "asn1/bad-printable-string");
  check("read a valid PrintableString decodes",
    decRead(TAGS.PRINTABLE_STRING, Buffer.from("Hello, World.", "latin1")) === "Hello, World.");
  // FIX J — UTF8String with invalid UTF-8 must be rejected, not U+FFFD-substituted.
  check("read UTF8String with invalid UTF-8 throws bad-utf8-string",
    code(function () { decRead(TAGS.UTF8_STRING, [0xFF, 0xFE]); }) === "asn1/bad-utf8-string");
  check("read a valid UTF8String decodes",
    decRead(TAGS.UTF8_STRING, Buffer.from("héllo", "utf8")) === "héllo");
  // FIX K — VisibleString is 0x20..0x7E (no control chars, no high bytes).
  check("read VisibleString with a control char throws bad-visible-string",
    code(function () { decRead(TAGS.VISIBLE_STRING, [0x41, 0x1F]); }) === "asn1/bad-visible-string");
  check("read VisibleString with a high byte throws bad-visible-string",
    code(function () { decRead(TAGS.VISIBLE_STRING, [0x80]); }) === "asn1/bad-visible-string");
  check("read a valid VisibleString decodes",
    decRead(TAGS.VISIBLE_STRING, Buffer.from("Hello", "latin1")) === "Hello");
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
  testUtcTimeYearRange();
  testGeneralizedTimeYearPad();
  testSequenceSetMustBeConstructed();
  testIa5SevenBit();
  testSetSorted();
  testIntegerBufferMinimal();
  testOidSubIdentifierCap();
  testReadStringValidation();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
