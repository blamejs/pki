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
  check("read.enumerated round-trips 6", pki.asn1.read.enumerated(pki.asn1.decode(b.enumerated(6n))) === 6n);
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
  // Non-minimal NEGATIVE INTEGER: 02 02 FF 80 -- a leading 0xFF is redundant when the next
  // octet's high bit is already set (-128 is minimally 02 01 80). X.690 sec. 8.3.2.
  check("rejects non-minimal negative integer", code(function () { pki.asn1.read.integer(pki.asn1.decode(Buffer.from("0202ff80", "hex"))); }) === "asn1/non-minimal-integer");
  // read.integer is strict on the tag: ENUMERATED shares INTEGER's content
  // encoding but is a distinct universal type, so an INTEGER-pinned field encoded
  // as ENUMERATED (and vice-versa) is a tag mismatch, never silently coerced.
  check("read.integer rejects an ENUMERATED node", code(function () { pki.asn1.read.integer(pki.asn1.decode(pki.asn1.build.enumerated(0n))); }) === "asn1/unexpected-tag");
  check("read.enumerated rejects an INTEGER node", code(function () { pki.asn1.read.enumerated(pki.asn1.decode(pki.asn1.build.integer(0n))); }) === "asn1/unexpected-tag");
  // read.enumerated shares INTEGER's content rules (non-minimal encoding refused).
  check("read.enumerated rejects non-minimal content", code(function () { pki.asn1.read.enumerated(pki.asn1.decode(Buffer.from("0a020001", "hex"))); }) === "asn1/non-minimal-integer");
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
  // Item cap: a dense run of tiny TLVs fans a small input into a huge eager node
  // tree; the decoder ticks a counter per node and fails closed at the cap.
  check("enforces item cap", code(function () {
    var nulls = [];
    for (var i = 0; i < 201; i++) nulls.push(pki.asn1.build.nullValue());
    pki.asn1.decode(pki.asn1.build.sequence(nulls), { maxItems: 100 });
  }) === "asn1/too-many-items");
  check("item cap admits a small tree", (function () {
    var d = pki.asn1.decode(pki.asn1.build.sequence([pki.asn1.build.nullValue(), pki.asn1.build.nullValue()]), { maxItems: 100 });
    return d.children.length === 2;
  })());
  check("maxItems config-time rejects a bad value", code(function () { pki.asn1.decode(pki.asn1.build.nullValue(), { maxItems: 1.5 }); }) !== "NO-THROW");
  // OID first-arc bound.
  check("rejects OID first arc > 2", code(function () { pki.asn1.encodeOidContent("3.1.1"); }) === "oid/bad-arc");
  // A leading-zero arc encodes to a DIFFERENT OID ("2.05.29.15" -> 2.5.29.15):
  // the encoder must reject it as non-canonical, agreeing with oid.name (the
  // string and DER forms of an OID must not disagree across the toolkit).
  check("rejects OID leading-zero arc", code(function () { pki.asn1.encodeOidContent("2.05.29.15"); }) === "oid/bad-input");
}

function testIntegerAndOidCaps() {
  var TAGS = pki.asn1.TAGS;
  // quadratic-BigInt DoS: an over-cap INTEGER is refused before
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
  // Date.UTC silently rolls over; every component must round-trip.
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

function testFractionalTimeAndImplicitInteger() {
  var b = pki.asn1.build, TAGS = pki.asn1.TAGS;
  function readGen(s, opts) { return pki.asn1.read.time(pki.asn1.decode(pki.asn1.encode(0x00, false, TAGS.GENERALIZED_TIME, Buffer.from(s, "latin1"))), opts); }
  function frac(s) { return readGen(s, { allowFractional: true }); }
  // Default (strict) read.time rejects a fractional GeneralizedTime — the RFC 5280
  // certificate/CRL Validity profile (§4.1.2.5.2) forbids fractional seconds.
  check("default read.time rejects fractional", code(function () { readGen("20260705120000.5Z"); }) === "asn1/bad-generalizedtime");
  // With allowFractional (RFC 3161 / X.690 §11.7) the fractional profile is accepted,
  // surfaced at ms precision.
  check("allowFractional .5Z -> 500ms", frac("20260705120000.5Z").getUTCMilliseconds() === 500);
  check("allowFractional .34Z -> 340ms", frac("20260705120000.34Z").getUTCMilliseconds() === 340);
  check("allowFractional trailing-zero .500Z rejected", code(function () { frac("20260705120000.500Z"); }) === "asn1/bad-generalizedtime");
  // X.690 §11.7 caps the fraction length at nothing; RFC 3161 §2.4.2's own example is
  // 5 fraction digits — accept any length (the Date is ms-precision; the raw bytes
  // carry the exact fraction losslessly).
  check("allowFractional >3-digit .1234Z accepted (ms Date)", frac("20260705120000.1234Z").getUTCMilliseconds() === 123);
  check("allowFractional RFC 3161 example .34352Z accepted", frac("19990609001326.34352Z").getUTCMilliseconds() === 343);
  check("allowFractional empty .Z rejected", code(function () { frac("20260705120000.Z"); }) === "asn1/bad-generalizedtime");
  check("allowFractional comma ,5Z rejected", code(function () { frac("20260705120000,5Z"); }) === "asn1/bad-generalizedtime");
  check("allowFractional no seconds rejected", code(function () { frac("202607051200Z"); }) === "asn1/bad-generalizedtime");
  check("allowFractional no Z rejected", code(function () { frac("20260705120000"); }) === "asn1/bad-generalizedtime");
  // read.integerImplicit — [tag] IMPLICIT INTEGER (the RFC 3161 Accuracy millis/micros shape).
  function ii(tag, n) { return pki.asn1.decode(b.contextPrimitive(tag, b.integer(BigInt(n)).slice(2))); }
  check("read.integerImplicit reads a [0] IMPLICIT INTEGER", pki.asn1.read.integerImplicit(ii(0, 999), 0) === 999n);
  check("read.integerImplicit rejects a universal INTEGER", code(function () { pki.asn1.read.integerImplicit(pki.asn1.decode(b.integer(5n)), 0); }) === "asn1/unexpected-tag");
  check("read.integerImplicit rejects the wrong context tag", code(function () { pki.asn1.read.integerImplicit(ii(1, 5), 0); }) === "asn1/unexpected-tag");
  check("read.integerImplicit rejects a constructed [0]", code(function () { pki.asn1.read.integerImplicit(pki.asn1.decode(b.contextConstructed(0, b.integer(5n))), 0); }) === "asn1/expected-primitive");
  check("read.integerImplicit enforces minimal INTEGER", code(function () { pki.asn1.read.integerImplicit(pki.asn1.decode(b.contextPrimitive(0, Buffer.from([0x00, 0x05]))), 0); }) === "asn1/non-minimal-integer");
}

function testBitStringUnusedBits() {
  var TAGS = pki.asn1.TAGS;
  // DER requires the declared unused low bits to be zero.
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
  // A fractional / non-finite unusedBits would be silently bit-truncated into a
  // DIFFERENT count when written into the leading octet — reject it like the
  // other numeric builder inputs (encodeLength, the tag number).
  check("build.bitString rejects a fractional unusedBits",
    code(function () { pki.asn1.build.bitString(Buffer.from([0xA0]), 3.5); }) === "asn1/bad-bit-string");
  check("build.bitString rejects a NaN unusedBits",
    code(function () { pki.asn1.build.bitString(Buffer.from([0xA0]), NaN); }) === "asn1/bad-bit-string");
  check("build.bitString rejects an unusedBits above 7",
    code(function () { pki.asn1.build.bitString(Buffer.from([0xA0]), 8); }) === "asn1/bad-bit-string");
  check("build.bitString still defaults an omitted unusedBits to 0",
    code(function () { pki.asn1.build.bitString(Buffer.from([0xA0])); }) === "NO-THROW");
}

function testUniversalStringScalarRange() {
  var TAGS = pki.asn1.TAGS;
  // scalar value out of range must be a typed Asn1Error, not a bare RangeError.
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
  // RFC 5280 §4.1.2.5.1 restricts UTCTime to 1950..2049; a year
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
  // a GeneralizedTime year below 1000 must zero-pad to 4 digits, or
  // it emits 12-14 char content that read.time rejects.
  check("build.generalizedTime year 99 round-trips to 99", (function () {
    // No try/catch: a regression that makes read.time reject the year-99 value
    // should surface that error here, not be swallowed into a bare `false`.
    var d = new Date(0); d.setUTCFullYear(99, 0, 1); d.setUTCHours(0, 0, 0, 0);
    return pki.asn1.read.time(pki.asn1.decode(b.generalizedTime(d))).getUTCFullYear() === 99;
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
  // X.690 8.9.1/8.11.1: universal SEQUENCE (0x10) / SET (0x11) MUST be
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

// The MIRROR of the rule above (X.690 §8.x/§10.2, DER): a universal
// primitive-only type encoded constructed is not valid DER. Without this a
// constructed string tag (a constructed UTF8String) decodes to a childless
// node that an X.509 DN attribute value would hex-render instead of failing
// closed, bypassing the restricted-string content checks.
function testConstructedPrimitiveOnlyRejected() {
  var b = pki.asn1.build, T = pki.asn1.TAGS;
  // Each primitive-only universal type, re-encoded with the constructed bit.
  [
    ["INTEGER",          T.INTEGER,          b.integer(1n)],
    ["UTF8String",       T.UTF8_STRING,      b.utf8("x")],
    ["OBJECT IDENTIFIER",T.OBJECT_IDENTIFIER,b.oid("2.5.4.3")],
    ["BOOLEAN",          T.BOOLEAN,          b.boolean(true)],
    ["OCTET STRING",     T.OCTET_STRING,     b.octetString(Buffer.from([1, 2]))],
    ["BIT STRING",       T.BIT_STRING,       b.bitString(Buffer.from([1]), 0)],
    ["PrintableString",  T.PRINTABLE_STRING, b.printable("x")],
    ["IA5String",        T.IA5_STRING,       b.ia5("x")],
  ].forEach(function (c) {
    var constructedTlv = pki.asn1.encode(0x00, true, c[1], c[2]); // universal class, constructed bit set
    check("constructed " + c[0] + " is rejected at decode",
      code(function () { pki.asn1.decode(constructedTlv); }) === "asn1/constructed-primitive-type");
  });
  // The constructed-ONLY types stay legal encoded constructed.
  check("constructed SET still decodes",
    code(function () { pki.asn1.decode(b.set([b.integer(1n)])); }) === "NO-THROW");
  check("constructed SEQUENCE still decodes (mirror)",
    code(function () { pki.asn1.decode(b.sequence([b.integer(1n)])); }) === "NO-THROW");

  // Universal types OUTSIDE the registry obey the same X.690 §10.2 form rule:
  // the constructed-capable universal set is a whitelist (SEQUENCE / SET), so a
  // constructed encoding of a restricted string type the codec never registered
  // cannot slip past the form check and reach a downstream consumer (an X.509
  // DN attribute hex-render) as a childless leaf.
  [
    ["ObjectDescriptor", 7],
    ["NumericString", 18],
    ["VideotexString", 21],
    ["GraphicString", 25],
    ["GeneralString", 27],
  ].forEach(function (c) {
    var tlv = pki.asn1.encode(0x00, true, c[1], b.octetString(Buffer.alloc(0)));
    check("constructed " + c[0] + " (unregistered universal type) is rejected at decode",
      code(function () { pki.asn1.decode(tlv); }) === "asn1/constructed-primitive-type");
  });
  // X.690 sec. 8.9/8.10/8.21 -- EXTERNAL (8), EMBEDDED PDV (11), and the
  // unrestricted CHARACTER STRING (29) are ALWAYS-constructed universal types
  // (SEQUENCE-based encodings), so a constructed encoding MUST decode -- one may
  // appear inside an ANY field (a CSR / CMS attribute value) the codec surfaces
  // raw. Rejecting them would fail otherwise-valid DER before a format parser sees it.
  [["EXTERNAL", 8], ["EMBEDDED PDV", 11], ["CHARACTER STRING", 29]].forEach(function (c) {
    var tlv = pki.asn1.encode(0x00, true, c[1], b.integer(1n));  // constructed, one inner TLV
    check("constructed " + c[0] + " decodes",
      code(function () { pki.asn1.decode(tlv); }) === "NO-THROW");
    var node = pki.asn1.decode(tlv);
    check("constructed " + c[0] + " surfaces its children", node.constructed && node.children.length === 1);
    // The mirror rule: an always-constructed type encoded PRIMITIVE is not valid DER.
    check("primitive " + c[0] + " is rejected at decode",
      code(function () { pki.asn1.decode(pki.asn1.encode(0x00, false, c[1], Buffer.alloc(0))); }) === "asn1/bad-tlv");
  });
}

// A non-finite / negative / fractional size or depth cap silently DISABLES the
// DoS guard (`depth > NaN` and `length > Infinity` are always false), letting a
// deeply nested input run to a bare RangeError instead of a typed verdict. A
// bad cap is a config fault and throws at entry (the tier-1 TypeError shape),
// so the CWE-400 caps can never be switched off by a typo.
function testDecodeCapOptsValidated() {
  var b = pki.asn1.build;
  var deep = b.integer(1n);
  for (var i = 0; i < 80; i++) deep = b.sequence([deep]);
  [NaN, Infinity, -1, 3.5, "64"].forEach(function (v) {
    check("decode rejects maxDepth " + String(v) + " as a TypeError", (function () {
      try { pki.asn1.decode(deep, { maxDepth: v }); return false; } catch (e) { return e instanceof TypeError; }
    })());
    check("decode rejects maxBytes " + String(v) + " as a TypeError", (function () {
      try { pki.asn1.decode(b.nullValue(), { maxBytes: v }); return false; } catch (e) { return e instanceof TypeError; }
    })());
  });
  // A maxDepth raised above the stack-safe recursion ceiling is refused at
  // config time: the decoder is recursive descent, so a cap above the engine's
  // native call-stack limit would let deeply nested input overflow with a raw
  // RangeError instead of a typed verdict (the class shared with pki.cbor).
  check("decode rejects a maxDepth above the stack-safe ceiling as a TypeError",
    (function () { try { pki.asn1.decode(deep, { maxDepth: 1000000 }); return false; } catch (e) { return e instanceof TypeError; } })());
  check("decode with valid explicit caps still decodes",
    code(function () { pki.asn1.decode(b.nullValue(), { maxBytes: 16, maxDepth: 4 }); }) === "NO-THROW");
  check("decode with the default caps (opts omitted) still decodes",
    code(function () { pki.asn1.decode(b.nullValue()); }) === "NO-THROW");
  // A detached-backed Buffer (backing ArrayBuffer transferred away) reads as
  // zero-length: the input coercion must fail closed typed here rather than hand
  // the walk an empty buffer (a misleading truncated-DER verdict on real input).
  check("decode rejects a detached-backed Buffer as asn1/not-buffer", code(function () {
    var ab = new ArrayBuffer(2); var buf = Buffer.from(ab); structuredClone(ab, { transfer: [ab] });
    pki.asn1.decode(buf);
  }) === "asn1/not-buffer");
}

// encode validates the tag number the way encodeLength validates the length: a
// negative tag corrupts the identifier octet (-1 emitted 0xff00), a fraction is
// silently bit-truncated to a DIFFERENT tag (3.7 -> 3), and a tag past the
// decoder's 4-octet high-tag cap emits DER decode() refuses — authoring faults
// that throw instead of breaking encode/decode round-trip symmetry.
function testEncodeIdentifierValidation() {
  check("encode rejects a negative tag",
    code(function () { pki.asn1.encode(0x00, false, -1, Buffer.alloc(0)); }) === "asn1/bad-tag");
  check("encode rejects a fractional tag",
    code(function () { pki.asn1.encode(0x80, false, 3.7, Buffer.alloc(0)); }) === "asn1/bad-tag");
  check("encode rejects a NaN tag",
    code(function () { pki.asn1.encode(0x80, false, NaN, Buffer.alloc(0)); }) === "asn1/bad-tag");
  check("encode rejects a non-number tag",
    code(function () { pki.asn1.encode(0x80, false, "31", Buffer.alloc(0)); }) === "asn1/bad-tag");
  check("encode rejects a tag past the decoder's high-tag cap",
    code(function () { pki.asn1.encode(0x80, false, 0x10000000, Buffer.alloc(0)); }) === "asn1/tag-too-large");
  // The cap is symmetric: the largest 4-octet high tag encodes AND decodes.
  check("encode of the max 4-octet high tag round-trips", (function () {
    var tlv = pki.asn1.encode(0x80, false, 0x0fffffff, Buffer.alloc(0));
    return pki.asn1.decode(tlv).tagNumber === 0x0fffffff;
  })());
  check("encode of a 2-octet high tag round-trips", (function () {
    var tlv = pki.asn1.encode(0x80, false, 128, Buffer.alloc(0));
    return pki.asn1.decode(tlv).tagNumber === 128;
  })());
}

function testIa5SevenBit() {
  var b = pki.asn1.build;
  // IA5String is 7-bit (0..127); a byte > 0x7F is not IA5.
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
  // DER (X.690 11.6) requires SET components in ascending encoded
  // order, regardless of caller order.
  var tlvA = b.integer(1n); // 02 01 01
  var tlvB = b.integer(2n); // 02 01 02  (tlvA < tlvB by Buffer.compare)
  check("build.set sorts components canonically",
    hex(b.set([tlvB, tlvA])) === hex(b.set([tlvA, tlvB])));
  // build.setOf sorts its members by DER encoding (X.690 11.6), like build.set.
  check("build.setOf sorts components canonically",
    hex(b.setOf([tlvB, tlvA])) === hex(b.setOf([tlvA, tlvB])));
  // Known-answer: SET tag 0x31, length 6, members in ascending order.
  check("build.setOf emits a SET (0x31) with ascending members",
    hex(b.setOf([tlvB, tlvA])) === "3106020101020102");
}

function testIntegerBufferMinimal() {
  var b = pki.asn1.build;
  // a raw INTEGER/ENUMERATED Buffer must be non-empty + minimal, or
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
  // build.oid can't emit a sub-identifier over the byte cap the
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
  // IA5String content bytes >= 0x80 are not 7-bit ASCII.
  check("read IA5String with a 0x80 byte throws bad-ia5-string",
    code(function () { decRead(TAGS.IA5_STRING, [0x41, 0x80]); }) === "asn1/bad-ia5-string");
  check("read a valid IA5String decodes", decRead(TAGS.IA5_STRING, [0x61, 0x62, 0x63]) === "abc");
  // PrintableString outside the restricted set (here "@").
  check("read PrintableString with '@' throws bad-printable-string",
    code(function () { decRead(TAGS.PRINTABLE_STRING, Buffer.from("A@B", "latin1")); }) === "asn1/bad-printable-string");
  check("read a valid PrintableString decodes",
    decRead(TAGS.PRINTABLE_STRING, Buffer.from("Hello, World.", "latin1")) === "Hello, World.");
  // UTF8String with invalid UTF-8 must be rejected, not U+FFFD-substituted.
  check("read UTF8String with invalid UTF-8 throws bad-utf8-string",
    code(function () { decRead(TAGS.UTF8_STRING, [0xFF, 0xFE]); }) === "asn1/bad-utf8-string");
  check("read a valid UTF8String decodes",
    decRead(TAGS.UTF8_STRING, Buffer.from("héllo", "utf8")) === "héllo");
  // VisibleString is 0x20..0x7E (no control chars, no high bytes).
  check("read VisibleString with a control char throws bad-visible-string",
    code(function () { decRead(TAGS.VISIBLE_STRING, [0x41, 0x1F]); }) === "asn1/bad-visible-string");
  check("read VisibleString with a high byte throws bad-visible-string",
    code(function () { decRead(TAGS.VISIBLE_STRING, [0x80]); }) === "asn1/bad-visible-string");
  check("read a valid VisibleString decodes",
    decRead(TAGS.VISIBLE_STRING, Buffer.from("Hello", "latin1")) === "Hello");
}

// Scoped BER relaxation ({ber:true}): RFC 7292 §4.1 content regions are
// normatively BER — indefinite lengths on constructed nodes and constructed
// (segmented) OCTET STRINGs. The opt-in mode accepts EXACTLY those two shapes
// and nothing else; every other DER strictness verdict (minimal definite
// lengths, minimal INTEGER, trailing bytes, depth/size caps) is unchanged, and
// the default strict mode keeps rejecting both shapes.
function testBerScopedDecode() {
  var b = pki.asn1.build;
  var TAGS = pki.asn1.TAGS;
  var inner = Buffer.concat([b.integer(3n), b.oid("1.2.840.113549.1.7.1")]);
  var indef = Buffer.concat([Buffer.from([0x30, 0x80]), inner, Buffer.from([0x00, 0x00])]);

  check("strict decode still rejects indefinite length", code(function () { pki.asn1.decode(indef); }) === "asn1/indefinite-length");
  check("ber decode accepts an indefinite-length SEQUENCE", code(function () { pki.asn1.decode(indef, { ber: true }); }) === "NO-THROW");
  var n = pki.asn1.decode(indef, { ber: true });
  check("ber indefinite SEQUENCE walks its children", n.children.length === 2 && n.children[0].tagNumber === TAGS.INTEGER);
  check("ber indefinite node bytes span the full TLV incl. EOC", n.bytes.equals(indef));

  var seg1 = b.octetString(Buffer.from([1, 2, 3]));
  var seg2 = b.octetString(Buffer.from([4, 5]));
  var constructed = Buffer.concat([Buffer.from([0x24, 0x80]), seg1, seg2, Buffer.from([0x00, 0x00])]);
  check("strict decode still rejects a constructed OCTET STRING", code(function () { pki.asn1.decode(constructed); }) === "asn1/constructed-primitive-type");
  var oc = pki.asn1.decode(constructed, { ber: true });
  check("ber constructed OCTET STRING reassembles content", oc.content.equals(Buffer.from([1, 2, 3, 4, 5])));
  check("ber reassembled node reads as a primitive string", oc.constructed === false && oc.tagNumber === TAGS.OCTET_STRING);

  // Definite-length constructed OCTET STRING (also legal BER).
  var definiteConstructed = pki.asn1.encode(0x00, true, TAGS.OCTET_STRING, Buffer.concat([seg1, seg2]));
  var dc = pki.asn1.decode(definiteConstructed, { ber: true });
  check("ber definite constructed OCTET STRING reassembles", dc.content.equals(Buffer.from([1, 2, 3, 4, 5])));

  // Nested constructed segments (X.690 permits recursion) reassemble too.
  var nested = Buffer.concat([Buffer.from([0x24, 0x80]),
    pki.asn1.encode(0x00, true, TAGS.OCTET_STRING, seg1), seg2, Buffer.from([0x00, 0x00])]);
  var nc = pki.asn1.decode(nested, { ber: true });
  check("ber nested constructed segments reassemble", nc.content.equals(Buffer.from([1, 2, 3, 4, 5])));

  // Each nesting level re-copies its payload, so nesting past the cap is
  // amplification and rejects typed.
  var chain = seg1;
  for (var d = 0; d < 12; d++) chain = pki.asn1.encode(0x00, true, TAGS.OCTET_STRING, chain);
  check("ber constructed-string nesting past the cap rejects",
    code(function () { pki.asn1.decode(chain, { ber: true }); }) === "asn1/bad-constructed-string");
  var okChain = seg1;
  for (var e2 = 0; e2 < 6; e2++) okChain = pki.asn1.encode(0x00, true, TAGS.OCTET_STRING, okChain);
  check("ber constructed-string nesting inside the cap reassembles",
    pki.asn1.decode(okChain, { ber: true }).content.equals(Buffer.from([1, 2, 3])));

  // IMPLICIT context-tagged constructed OCTET STRING — the form CMS streams
  // ciphertext as ([0] IMPLICIT OCTET STRING). The context tag hides the
  // underlying type from the decoder, so reassembly happens in the typed
  // reader — and ONLY for a node that came through a ber decode; the strict
  // path's verdict is unchanged.
  var ctxConstructed = Buffer.concat([Buffer.from([0xa0, 0x80]), seg1, seg2, Buffer.from([0x00, 0x00])]);
  var berWrap = Buffer.concat([Buffer.from([0x30, 0x80]), ctxConstructed, Buffer.from([0x00, 0x00])]);
  var berCtxNode = pki.asn1.decode(berWrap, { ber: true }).children[0];
  check("ber implicit constructed OCTET STRING reassembles via the reader",
    pki.asn1.read.octetStringImplicit(berCtxNode, 0).equals(Buffer.from([1, 2, 3, 4, 5])));
  var strictCtxNode = pki.asn1.decode(b.sequence([b.contextConstructed(0, Buffer.concat([seg1, seg2]))])).children[0];
  check("strict implicit constructed OCTET STRING still rejects",
    code(function () { pki.asn1.read.octetStringImplicit(strictCtxNode, 0); }) === "asn1/expected-primitive");
  var berBadSeg = Buffer.concat([Buffer.from([0x30, 0x80, 0xa0, 0x80]), b.integer(1n), Buffer.from([0x00, 0x00, 0x00, 0x00])]);
  var berBadNode = pki.asn1.decode(berBadSeg, { ber: true }).children[0];
  check("ber implicit constructed OCTET STRING rejects a foreign segment",
    code(function () { pki.asn1.read.octetStringImplicit(berBadNode, 0); }) === "asn1/bad-constructed-string");

  // What the relaxation does NOT license:
  var indefPrimitive = Buffer.concat([Buffer.from([0x04, 0x80]), Buffer.from([0x00, 0x00])]);
  check("ber rejects indefinite length on a primitive node", code(function () { pki.asn1.decode(indefPrimitive, { ber: true }); }) !== "NO-THROW");
  var missingEoc = Buffer.concat([Buffer.from([0x30, 0x80]), inner]);
  check("ber rejects a missing EOC as truncated", code(function () { pki.asn1.decode(missingEoc, { ber: true }); }) === "asn1/truncated");
  var badSegment = Buffer.concat([Buffer.from([0x24, 0x80]), b.integer(1n), Buffer.from([0x00, 0x00])]);
  check("ber rejects a foreign-type segment in a constructed string", code(function () { pki.asn1.decode(badSegment, { ber: true }); }) !== "NO-THROW");
  var nonMinimal = Buffer.from([0x30, 0x81, 0x03, 0x02, 0x01, 0x05]);
  check("ber keeps rejecting non-minimal definite lengths", code(function () { pki.asn1.decode(nonMinimal, { ber: true }); }) === "asn1/non-minimal-length");
  var trailing = Buffer.concat([indef, Buffer.from([0x00])]);
  check("ber keeps rejecting trailing bytes", code(function () { pki.asn1.decode(trailing, { ber: true }); }) === "asn1/trailing-bytes");
  var depthBomb = b.integer(1n);
  for (var i = 0; i < 70; i++) depthBomb = Buffer.concat([Buffer.from([0x30, 0x80]), depthBomb, Buffer.from([0x00, 0x00])]);
  check("ber keeps the depth cap", code(function () { pki.asn1.decode(depthBomb, { ber: true }); }) === "asn1/too-deep");
}

// A decoded node's tagClass reflects the identifier's class bits: universal
// (0x00), application (0x40), context (0x80), private (0xc0). The context path
// is exercised by the IMPLICIT readers; application and private classes appear
// in ANY-typed fields the codec surfaces raw, so their class label must be
// correct too (a mislabelled class would confuse a schema's tag dispatch).
function testTagClassLabels() {
  var appNode = pki.asn1.decode(pki.asn1.encode(0x40, false, 5, Buffer.from([1, 2])));
  check("application-class node labels tagClass application", appNode.tagClass === "application");
  var privNode = pki.asn1.decode(pki.asn1.encode(0xc0, false, 5, Buffer.from([1, 2])));
  check("private-class node labels tagClass private", privNode.tagClass === "private");
}

// X.690 8.1.2.4 high-tag-number form (identifier low 5 bits == 0x1f, then
// base-128 continuation octets): DER requires the minimal encoding. A leading
// 0x80 continuation octet, a run past the 4-octet cap, and a low tag (< 0x1f)
// dressed in the long form are all non-DER and reject typed.
function testHighTagNumberForm() {
  // Leading 0x80 in the high-tag body is a non-minimal (redundant) octet.
  check("high-tag-number leading 0x80 rejects non-minimal-tag",
    code(function () { pki.asn1.decode(Buffer.from([0x1f, 0x80])); }) === "asn1/non-minimal-tag");
  // Five continuation octets exceed the 4-octet high-tag cap.
  check("high-tag-number past the 4-octet cap rejects tag-too-large",
    code(function () { pki.asn1.decode(Buffer.from([0x1f, 0x81, 0x81, 0x81, 0x81, 0x81])); }) === "asn1/tag-too-large");
  // Tag 1 encoded in the high-tag form (it fits the low form) is non-minimal.
  check("low tag in high-tag form rejects non-minimal-tag",
    code(function () { pki.asn1.decode(Buffer.from([0x1f, 0x01])); }) === "asn1/non-minimal-tag");
}

// X.690 8.1.3 long-form length: the declared length-octet count must fit the
// buffer and the leading length octet must be non-zero (minimal).
function testLongFormLengthEdges() {
  // 0x82 declares two length octets but only one follows.
  check("long-form length overrunning the buffer rejects truncated",
    code(function () { pki.asn1.decode(Buffer.from([0x04, 0x82, 0x01])); }) === "asn1/truncated");
  // 0x82 0x00 0x80 is a non-minimal length (a leading zero length octet).
  check("long-form length with a leading zero octet rejects non-minimal-length",
    code(function () { pki.asn1.decode(Buffer.from([0x04, 0x82, 0x00, 0x80])); }) === "asn1/non-minimal-length");
}

// Typed-reader content-shape edges the round-trip suite doesn't reach: a
// wrong-width BOOLEAN, an empty INTEGER / BIT STRING, a non-minimal NEGATIVE
// INTEGER, and unused bits declared over an empty BIT STRING body.
function testReaderContentEdges() {
  // BOOLEAN content must be exactly one octet (zero or two octets reject).
  check("BOOLEAN with empty content rejects bad-boolean",
    code(function () { pki.asn1.read.boolean(pki.asn1.decode(Buffer.from([0x01, 0x00]))); }) === "asn1/bad-boolean");
  check("BOOLEAN with two content octets rejects bad-boolean",
    code(function () { pki.asn1.read.boolean(pki.asn1.decode(Buffer.from([0x01, 0x02, 0x00, 0x00]))); }) === "asn1/bad-boolean");
  // INTEGER must have at least one content octet.
  check("empty INTEGER rejects bad-integer",
    code(function () { pki.asn1.read.integer(pki.asn1.decode(Buffer.from([0x02, 0x00]))); }) === "asn1/bad-integer");
  // A negative INTEGER with a redundant leading 0xFF octet is non-minimal
  // (0xFF 0x80 should be 0x80) -- the reader counterpart of the positive case.
  check("reader rejects a non-minimal negative INTEGER",
    code(function () { pki.asn1.read.integer(pki.asn1.decode(Buffer.from([0x02, 0x02, 0xff, 0x80]))); }) === "asn1/non-minimal-integer");
  // BIT STRING must carry at least the unused-bit-count octet.
  check("empty BIT STRING rejects bad-bit-string",
    code(function () { pki.asn1.read.bitString(pki.asn1.decode(Buffer.from([0x03, 0x00]))); }) === "asn1/bad-bit-string");
  // A non-zero unused-bit count over an empty body (only the count octet) is
  // contradictory -- there are no bits to leave unused.
  check("BIT STRING declaring unused bits over an empty body rejects bad-bit-string",
    code(function () { pki.asn1.read.bitString(pki.asn1.decode(Buffer.from([0x03, 0x01, 0x03]))); }) === "asn1/bad-bit-string");
}

// read.octetStringImplicit expects a context-class node at the given tag; a
// universal node or the wrong context tag is a tag mismatch, never coerced.
function testOctetStringImplicitTagMismatch() {
  check("read.octetStringImplicit rejects a universal node",
    code(function () { pki.asn1.read.octetStringImplicit(pki.asn1.decode(pki.asn1.build.octetString(Buffer.from([1]))), 0); }) === "asn1/unexpected-tag");
  check("read.octetStringImplicit rejects the wrong context tag",
    code(function () { pki.asn1.read.octetStringImplicit(pki.asn1.decode(pki.asn1.build.contextPrimitive(1, Buffer.from([1]))), 0); }) === "asn1/unexpected-tag");
}

// OID content edges: empty content, content ending mid sub-identifier (a
// dangling continuation octet), and the first-arc < 40 case (arc1 == 0, e.g.
// the 0.x itu-t arcs) that the 1.x / 2.x fixtures don't reach.
function testOidContentEdges() {
  check("empty OID content rejects oid/empty",
    code(function () { pki.asn1.decodeOidContent(Buffer.alloc(0)); }) === "oid/empty");
  // 0x2a terminates the first sub-identifier; the trailing 0x81 keeps the
  // continuation bit set with no terminal octet, so the OID ends mid arc.
  check("OID ending mid sub-identifier rejects oid/truncated",
    code(function () { pki.asn1.decodeOidContent(Buffer.from([0x2a, 0x81])); }) === "oid/truncated");
  // First sub-identifier 39 (< 40) decodes to arc1 == 0 (0.39).
  check("OID first sub-identifier below 40 yields arc1 == 0",
    pki.asn1.decodeOidContent(Buffer.from([0x27])) === "0.39");
}

// readString / readTime require a universal node; a context-tagged node is not
// a string / time type and rejects typed. readString also spans TeletexString
// (decoded latin1) and the UniversalString length-multiple-of-4 rule.
function testStringTimeTypeEdges() {
  var TAGS = pki.asn1.TAGS;
  check("readString on a context-tagged node rejects expected-string",
    code(function () { pki.asn1.read.string(pki.asn1.decode(pki.asn1.build.contextPrimitive(0, Buffer.from([0x41])))); }) === "asn1/expected-string");
  check("readTime on a context-tagged node rejects expected-time",
    code(function () { pki.asn1.read.time(pki.asn1.decode(pki.asn1.build.contextPrimitive(0, Buffer.from("260704070027Z", "latin1")))); }) === "asn1/expected-time");
  // TeletexString (T.61, tag 0x14) is surfaced as latin1 text.
  check("readString decodes a TeletexString as latin1",
    pki.asn1.read.string(pki.asn1.decode(pki.asn1.encode(0x00, false, TAGS.TELETEX_STRING, Buffer.from([0x41, 0x42])))) === "AB");
  // UniversalString (UCS-4) content length must be a multiple of 4.
  check("UniversalString with a non-multiple-of-4 length rejects bad-universal-string",
    code(function () { pki.asn1.read.string(pki.asn1.decode(pki.asn1.encode(0x00, false, TAGS.UNIVERSAL_STRING, Buffer.from([0x00, 0x00, 0x41])))); }) === "asn1/bad-universal-string");
}

// encodeLength (the public low-level length encoder) validates its input like
// the other numeric builders: a non-integer / non-finite / negative length is
// an authoring fault, and a length needing more than 126 octets can't be a DER
// long-form length.
function testEncodeLengthEdges() {
  check("encodeLength rejects a negative length",
    code(function () { pki.asn1.encodeLength(-1); }) === "asn1/bad-length");
  check("encodeLength rejects a fractional length",
    code(function () { pki.asn1.encodeLength(1.5); }) === "asn1/bad-length");
  check("encodeLength rejects a NaN length",
    code(function () { pki.asn1.encodeLength(NaN); }) === "asn1/bad-length");
  check("encodeLength rejects a non-number length",
    code(function () { pki.asn1.encodeLength("5"); }) === "asn1/bad-length");
  // A length that would need more than 126 long-form octets can't be encoded.
  check("encodeLength rejects a length needing more than 126 octets",
    code(function () { pki.asn1.encodeLength(Number.MAX_VALUE); }) === "asn1/length-too-large");
  // A normal long-form length still encodes canonically (0x81 0xC8 for 200).
  check("encodeLength encodes 200 as a canonical long form",
    hex(pki.asn1.encodeLength(200)) === "81c8");
}

// sequenceTlv recovers a universal SEQUENCE from a decoded node: a constructed
// node contributes its children's DER, and a primitive node contributes its
// content octets directly (both the branches of the content/children choice).
function testSequenceTlv() {
  var b = pki.asn1.build, TAGS = pki.asn1.TAGS;
  // Constructed IMPLICIT [6] node -> universal SEQUENCE over its children.
  var ctxNode = pki.asn1.decode(b.contextConstructed(6, b.integer(1n)));
  var fromChildren = pki.asn1.sequenceTlv(ctxNode);
  var dc = pki.asn1.decode(fromChildren);
  check("sequenceTlv rebuilds a SEQUENCE from a constructed node's children",
    dc.tagNumber === TAGS.SEQUENCE && pki.asn1.read.integer(dc.children[0]) === 1n);
  // Primitive node whose content is itself a valid inner TLV -> that content
  // becomes the SEQUENCE body verbatim.
  var primNode = pki.asn1.decode(b.octetString(b.integer(1n)));
  var fromContent = pki.asn1.sequenceTlv(primNode);
  var dp = pki.asn1.decode(fromContent);
  check("sequenceTlv wraps a primitive node's content as the SEQUENCE body",
    dp.tagNumber === TAGS.SEQUENCE && pki.asn1.read.integer(dp.children[0]) === 1n);
}

// encode accepts a non-Buffer content (a byte array or an omitted content) via
// Buffer.from, alongside the Buffer path -- the escape-hatch encoder must not
// require a pre-built Buffer for a simple byte list.
function testEncodeNonBufferContent() {
  var TAGS = pki.asn1.TAGS;
  var fromArray = pki.asn1.encode(0x00, false, TAGS.OCTET_STRING, [1, 2, 3]);
  check("encode accepts an array content",
    hex(pki.asn1.read.octetString(pki.asn1.decode(fromArray))) === "010203");
  var fromUndefined = pki.asn1.encode(0x00, false, TAGS.NULL, undefined);
  check("encode accepts an omitted content as empty",
    pki.asn1.read.nullValue(pki.asn1.decode(fromUndefined)) === null);
}

// build.integer's numeric path (intToDer): an unsafe JS number and a
// non-number / non-BigInt are authoring faults, and a negative value needing
// more than one octet exercises the width-growth loop.
function testIntToDerEdges() {
  var b = pki.asn1.build;
  // 2^53 is beyond Number.MAX_SAFE_INTEGER -- the caller must pass a BigInt.
  check("build.integer rejects an unsafe JS number",
    code(function () { b.integer(Math.pow(2, 53)); }) === "asn1/bad-integer");
  check("build.integer rejects a null value",
    code(function () { b.integer(null); }) === "asn1/bad-integer");
  check("build.integer rejects a plain-object value",
    code(function () { b.integer({}); }) === "asn1/bad-integer");
  // -200 needs two two's-complement octets (0xFF 0x38); it round-trips.
  check("build.integer encodes a multi-octet negative value",
    pki.asn1.read.integer(pki.asn1.decode(b.integer(-200n))) === -200n);
  check("build.integer -200 emits two content octets",
    hex(pki.asn1.decode(b.integer(-200n)).content) === "ff38");
}

// build.printable rejects a value outside the PrintableString set, and the
// SEQUENCE / SET builders reject a non-array argument (a defended authoring
// fault, not a silent single-child coercion).
function testBuildPrintableAndChildrenGuard() {
  var b = pki.asn1.build;
  check("build.printable rejects a character outside the set",
    code(function () { b.printable("A@B"); }) === "asn1/bad-printable-string");
  check("build.sequence rejects a non-array argument",
    code(function () { b.sequence("notarray"); }) === "asn1/bad-children");
  check("build.set rejects a null argument",
    code(function () { b.set(null); }) === "asn1/bad-children");
}

function run() {
  testTagClassLabels();
  testHighTagNumberForm();
  testLongFormLengthEdges();
  testReaderContentEdges();
  testOctetStringImplicitTagMismatch();
  testOidContentEdges();
  testStringTimeTypeEdges();
  testEncodeLengthEdges();
  testSequenceTlv();
  testEncodeNonBufferContent();
  testIntToDerEdges();
  testBuildPrintableAndChildrenGuard();
  testBerScopedDecode();
  testBuildVectors();
  testRoundTrip();
  testOidContent();
  testRejects();
  testIntegerAndOidCaps();
  testTimeOutOfRange();
  testFractionalTimeAndImplicitInteger();
  testBitStringUnusedBits();
  testUniversalStringScalarRange();
  testUtcTimeYearRange();
  testGeneralizedTimeYearPad();
  testSequenceSetMustBeConstructed();
  testConstructedPrimitiveOnlyRejected();
  testDecodeCapOptsValidated();
  testEncodeIdentifierValidation();
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
