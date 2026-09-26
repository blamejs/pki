// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: attribute certificate linting via pki.lint.attrcert.
 *
 * libFuzzer / jazzer.js harness. The linter's DATA path must NEVER throw: a hostile,
 * truncated or non-DER input must return a LintReport (a `fatal` lint/unparseable
 * finding) rather than raise. This target drives the raw bytes into lint.attrcert, which
 * is the ingestion boundary, splices them over the tail of a real attribute certificate
 * so the rule closures run on attacker-controlled values, and then puts them in each
 * extension the profile reads, which is where the criticality table and the
 * outside-the-profile rule both look.
 *
 * Contract: lint.attrcert(bytes) has exactly ONE acceptable outcome, it RETURNS a report.
 * Any throw at all is an unguarded invariant break: rethrow so jazzer records the
 * reproducer.
 */

var pki = require("..");
var b = pki.asn1.build;
var oid = pki.oid;

var SIG_ALG = b.sequence([b.oid(oid.byName("ecdsaWithSHA256"))]);
var DN = b.sequence([b.set([b.sequence([b.oid(oid.byName("commonName")), b.utf8("Fuzz AA")])])]);
var HOLDER_DN = b.sequence([b.set([b.sequence([b.oid(oid.byName("commonName")), b.utf8("Fuzz Holder")])])]);

function ext(name, critical, inner) {
  var kids = [b.oid(oid.byName(name))];
  if (critical) kids.push(b.boolean(true));
  kids.push(b.octetString(inner));
  return b.sequence(kids);
}
function acWith(exts) {
  var holder = b.sequence([b.implicit(1, b.sequence([b.contextConstructed(4, HOLDER_DN)]), true)]);
  var issuer = b.implicit(0, b.sequence([b.sequence([b.contextConstructed(4, DN)])]), true);
  var attrs = b.sequence([b.sequence([b.oid(oid.byName("role")),
    b.setOf([b.sequence([b.explicit(1, b.contextPrimitive(6, Buffer.from("urn:role:fuzz")))])])])]);
  var kids = [
    b.integer(1n), holder, issuer, SIG_ALG, b.integer(1n),
    b.sequence([b.generalizedTime(new Date("2026-01-01T00:00:00Z")),
      b.generalizedTime(new Date("2027-01-01T00:00:00Z"))]),
    attrs,
  ];
  if (exts) kids.push(b.sequence(exts));
  return b.sequence([b.sequence(kids), SIG_ALG, b.bitString(Buffer.alloc(8, 1), 0)]);
}
var BASE = acWith([ext("authorityKeyIdentifier", false, b.sequence([
  b.contextPrimitive(0, Buffer.alloc(20, 3))]))]);

function lintNeverThrows(input) {
  var report = pki.lint.attrcert(input);
  if (!report || !Array.isArray(report.findings) || !report.counts) {
    throw new Error("lint.attrcert returned a malformed report");
  }
}

// The extensions the profile's criticality table names, each driven on its own so a value
// the parser refuses arrives as the fatal finding rather than as a throw.
var FUZZED_EXTS = [
  { name: "acAuditIdentity", critical: true },
  { name: "targetInformation", critical: true },
  { name: "authorityKeyIdentifier", critical: false },
  { name: "authorityInfoAccess", critical: false },
  { name: "cRLDistributionPoints", critical: false },
  { name: "noRevAvail", critical: false },
];

module.exports.fuzz = function (data) {
  // (1) raw bytes -> the ingestion never-throw boundary.
  lintNeverThrows(data);

  // (2) splice onto a real attribute certificate so the rules run on hostile values.
  if (data.length >= 2) {
    var der = Buffer.from(BASE);
    var start = Math.max(0, der.length - data.length);
    data.copy(der, start, 0, Math.min(data.length, der.length - start));
    lintNeverThrows(der);
  }

  // (3) the bytes AS one extension value at a time.
  if (data.length >= 1 && data.length <= 4096) {
    FUZZED_EXTS.forEach(function (slot) {
      var one;
      try { one = acWith([ext(slot.name, slot.critical, data)]); }
      catch (_e) {
        // The BUILDER refusing these bytes is not the contract under test.
        return;
      }
      lintNeverThrows(one);
    });
  }
};
