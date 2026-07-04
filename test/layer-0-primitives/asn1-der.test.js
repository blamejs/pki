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

function run() {
  testBuildVectors();
  testRoundTrip();
  testOidContent();
  testRejects();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
