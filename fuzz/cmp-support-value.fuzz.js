// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: the RFC 9483 sec. 4.3 support-message infoValue decoders.
 *
 * Runs under libFuzzer via jazzer.js; ClusterFuzzLite + OSS-Fuzz consume
 * module.exports.fuzz = function (data). The contract: parsing hostile bytes
 * either succeeds or throws a pki.errors.PkiError -- any other throw (or a
 * hang) is a finding and is rethrown so the fuzzer records a reproducer.
 *
 * These four read a genp's ANY payload, which reaches them straight off the
 * wire once a response's protection verifies, so each is an independent entry
 * point for attacker-chosen bytes. They are internal to pki.cmp.session, which
 * needs a transport to drive, so the harness reaches the module directly --
 * the same shape the guard and pkix-extension targets use.
 */
var pki = require("..");
var schemaCmp = require("../lib/schema-cmp.js");

var READERS = [
  schemaCmp.readCaCerts,
  schemaCmp.readRootCaKeyUpdate,
  schemaCmp.readCertReqTemplate,
  schemaCmp.readCrls,
];

module.exports.fuzz = function (data) {
  if (data.length < 2) return;
  // A leading selector byte picks the reader and is NOT part of the value. Keeping
  // it inside the value would tie the choice to the DER's own first byte, and every
  // well-formed value starts with the same SEQUENCE tag -- so three of the four
  // readers would never run on a corpus entry that had mutated toward valid.
  var read = READERS[data[0] % READERS.length];
  try {
    read(data.slice(1));
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
};
