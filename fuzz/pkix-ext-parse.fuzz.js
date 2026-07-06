// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: the RFC 5280 section 4.2.1 extension-value decoders
 * (pki.schema.pkix.certExtensionDecoders) that pki.path certification-path
 * validation drives over each certificate's raw extnValue octets.
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite (CI PRs + nightly batch)
 * and OSS-Fuzz (continuous) consume `module.exports.fuzz = function (data)`
 * where `data` is a Buffer the engine mutates. Every decoder takes an
 * attacker-controlled DER value (basicConstraints, keyUsage, nameConstraints,
 * the policy family, the altNames, extKeyUsage, and the key-identifier pair),
 * so one mutated buffer is fed to each in turn.
 *
 * Contract: decoding a hostile extension value has exactly two acceptable
 * outcomes — a successful decode, or a thrown `pki.errors.PkiError`
 * (PathError / Asn1Error / OidError). Any other throw (a RangeError, a bare
 * TypeError from an unguarded field read, a stack overflow from the nested
 * GeneralName walk, a hang) is an unguarded invariant break on hostile input:
 * rethrow it so jazzer records the reproducer.
 */

var pki = require("..");
var pkix = require("../lib/schema-pkix");
var oid = require("../lib/oid");

var NS = pkix.makeNS("path", pki.errors.PathError, oid);
var DECODERS = pkix.certExtensionDecoders(NS).byOid;
var OIDS = Object.keys(DECODERS);

module.exports.fuzz = function (data) {
  for (var i = 0; i < OIDS.length; i++) {
    try {
      DECODERS[OIDS[i]](data);
    } catch (e) {
      if (e instanceof pki.errors.PkiError) continue;
      throw e;
    }
  }
};
