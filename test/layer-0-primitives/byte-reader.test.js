// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- lib/byte-reader (@internal): the bounded big-endian cursor under the
 * non-ASN.1 length-prefixed wire formats (pki.ct SCT lists, pki.webauthn TPM/CBOR
 * structures). An engine primitive with no operator namespace, so it is pinned
 * directly here (the guard-* / validator-* engine-test pattern): every read is
 * length-checked against [pos, end) BEFORE a byte is taken, faulting through the
 * caller's typed ErrorClass.
 */

var ByteReader = require("../../lib/byte-reader.js");
var errors = require("../../lib/framework-error");
var helpers = require("../helpers");
var check = helpers.check;

// The caller threads a typed error CONSTRUCTOR (ByteReader does `new this.E(code, msg)`).
var TestError = errors.defineClass("TestError", { withCause: true });
function E(code, message) { return new TestError(code, message); }
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.name; } }
function buf(hex) { return Buffer.from(hex, "hex"); }

function run() {
  // Constructor: a non-Buffer is a programming error (TypeError), not a coded fault.
  check("ByteReader rejects a non-Buffer buf", code(function () { return new ByteReader("nope", 0, 4, E, "x/trunc"); }) === "TypeError");
  // `end` omitted (null/undefined) defaults to buf.length; an explicit end bounds shorter.
  check("end omitted defaults to buf.length", new ByteReader(buf("0102030405"), 0, undefined, E, "x/t").remaining() === 5);
  check("end given bounds the window", new ByteReader(buf("0102030405"), 0, 2, E, "x/t").remaining() === 2);
  // `defaultCode` omitted defaults to byte-reader/truncated; given, it is used.
  check("defaultCode omitted -> byte-reader/truncated on overrun",
    code(function () { return new ByteReader(buf("01"), 0, 1, E).u32(); }) === "byte-reader/truncated");
  check("defaultCode given -> used on overrun",
    code(function () { return new ByteReader(buf("01"), 0, 1, E, "ct/truncated").u32(); }) === "ct/truncated");

  // Fixed-width reads advance the cursor and stay in bounds.
  var r = new ByteReader(buf("01" + "0203" + "040506" + "0708090a" + "0102030405060708"), 0, undefined, E, "x/t");
  check("u8", r.u8() === 0x01);
  check("u16", r.u16() === 0x0203);
  check("u24", r.u24() === 0x040506);
  check("u32", r.u32() === 0x0708090a);
  check("u64 -> BigInt", r.u64() === 0x0102030405060708n);
  check("atEnd after consuming all", r.atEnd() === true);
  // A read past `end` faults with the caller's code, per-read override honored.
  check("u8 past end faults with the override code", code(function () { return r.u8("x/eof"); }) === "x/eof");

  // fixed(n) is a zero-copy slice; an over-long fixed read faults.
  var rf = new ByteReader(buf("aabbccdd"), 0, undefined, E, "x/t");
  check("fixed(2) slices the next 2 bytes", rf.fixed(2).toString("hex") === "aabb");
  check("fixed past end faults", code(function () { return rf.fixed(9); }) === "x/t");

  // vector<min..max>: a 2- or 3-byte big-endian length prefix, then the body.
  check("vector(2) reads a 2-byte-prefixed body", new ByteReader(buf("0003" + "aabbcc"), 0, undefined, E, "x/t").vector(2, 0, 10).toString("hex") === "aabbcc");
  check("vector(3) reads a 3-byte-prefixed body", new ByteReader(buf("000003" + "aabbcc"), 0, undefined, E, "x/t").vector(3, 0, 10).toString("hex") === "aabbcc");
  // A declared length below the minimum or above the maximum is malformed.
  check("vector length below the minimum faults", code(function () { return new ByteReader(buf("0003aabbcc"), 0, undefined, E, "x/t").vector(2, 5, 10, "x/bad"); }) === "x/bad");
  check("vector length above the maximum faults", code(function () { return new ByteReader(buf("0003aabbcc"), 0, undefined, E, "x/t").vector(2, 0, 2, "x/bad"); }) === "x/bad");
  // A lying length whose body overruns the buffer faults.
  check("vector body overrun faults", code(function () { return new ByteReader(buf("00ff" + "aabb"), 0, undefined, E, "x/t").vector(2, 0, 1000, "x/bad"); }) === "x/bad");

  // subReader: a bounded child over the next `len` bytes, sharing the ErrorClass.
  var rs = new ByteReader(buf("02" + "aabb"), 0, undefined, E, "x/t");
  var child = rs.subReader(rs.u8());
  check("subReader spans exactly len bytes", child.remaining() === 2 && child.fixed(2).toString("hex") === "aabb");
  check("subReader over-length faults", code(function () { return new ByteReader(buf("aabb"), 0, undefined, E, "x/t").subReader(9); }) === "x/t");

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) run();
