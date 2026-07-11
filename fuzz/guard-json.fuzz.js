// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: the strict bounded JSON reader (lib/guard-json), driven directly.
 *
 * Runs under libFuzzer via jazzer.js; ClusterFuzzLite + OSS-Fuzz consume
 * module.exports.fuzz = function (data). Two contracts:
 *
 * 1. Throw contract -- hostile bytes either parse or throw a pki.errors.PkiError
 *    (the caller's injected class); any other throw (a bare RangeError from the
 *    recursive descent, a TypeError) or a hang is a finding.
 * 2. Differential accept oracle -- the reader is STRICTER than JSON.parse (it
 *    rejects duplicate members, deep nesting, oversized input), so whenever it
 *    ACCEPTS, JSON.parse over the same text must also accept and produce a
 *    deep-equal value. An accepted document JSON.parse rejects, or a diverging
 *    value, is a parser-differential finding (the CWE-436 smuggling class the
 *    guard exists to prevent) and is thrown as a plain Error so the fuzzer
 *    records a reproducer.
 *
 * The fatal UTF-8 decode inside the guard guarantees that an accepted input is
 * valid UTF-8, so the reference text for the differential is lossless.
 */
var pki = require("..");
var guardJson = require("../lib/guard-json");

var JoseError = pki.errors.JoseError;
var SPEC = {
  maxBytes: 1 << 20,
  maxDepth: 64,
  badJson: "jose/bad-json",
  tooDeep: "jose/too-deep",
  duplicateMember: "jose/duplicate-member",
  tooLarge: "jose/too-large",
  badInput: "jose/bad-input",
  label: "fuzz JSON document",
};

module.exports.fuzz = function (data) {
  var out;
  try { out = guardJson.parse(data, JoseError, SPEC); }
  catch (e) {
    if (!(e instanceof pki.errors.PkiError)) throw e;
    return;
  }
  // Accepted: the differential oracle. The guard is a strict subset of
  // JSON.parse's accept set, and on the common set the values must agree.
  var text = data.toString("utf8");
  var ref;
  try { ref = JSON.parse(text); }
  catch (e) {
    throw new Error("guard-json accepted a document JSON.parse rejects: " + e.message);
  }
  if (JSON.stringify(out) !== JSON.stringify(ref)) {
    throw new Error("guard-json value diverges from JSON.parse for the same text");
  }
};
