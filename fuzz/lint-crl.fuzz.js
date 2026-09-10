// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: certificate revocation list linting via pki.lint.crl.
 *
 * libFuzzer / jazzer.js harness. The linter is the one toolkit surface whose DATA
 * path must NEVER throw: it surveys a corpus that includes malformed members, so a
 * hostile / truncated / non-DER input must return a LintReport (a `fatal`
 * lint/unparseable finding) rather than raise. This target drives three paths with the
 * fuzzer's bytes: (1) the raw bytes straight into lint.crl (exercises the never-throw
 * ingestion boundary), (2) the bytes spliced over the tail of a real CRL so the outer
 * framing still parses and the RULE closures run on attacker-controlled decoded
 * structures, and (3) the bytes as the value of a recognized extension, which is where
 * the rules that DECODE a value run.
 *
 * Contract: lint.crl(bytes) has exactly ONE acceptable outcome -- it RETURNS a report.
 * Any throw at all (a PkiError the linter should have caught, a RangeError, a bare
 * TypeError, a hang) is an unguarded invariant break: rethrow so jazzer records the
 * reproducer. (LintError is config-time only and unreachable from a bytes input.)
 */

var pki = require("..");
var b = pki.asn1.build;
var oid = pki.oid;

// A v2 CRL assembled here rather than taken from a fixture, because the signature is
// never verified by linting and the builders are synchronous. The outer framing keeps
// the fuzzer's bytes reaching the rule closures after a splice.
var ALG = b.sequence([b.oid(oid.byName("ecdsaWithSHA256"))]);
var ISSUER = b.sequence([b.set([b.sequence([b.oid(oid.byName("commonName")), b.utf8("Fuzz CA")])])]);
var SIG = b.bitString(Buffer.alloc(8, 1), 0);
function utc(s) { return b.utcTime(new Date(s)); }
function ext(name, critical, inner) {
  var kids = [b.oid(oid.byName(name))];
  if (critical) kids.push(b.boolean(true));
  kids.push(b.octetString(inner));
  return b.sequence(kids);
}
function crlWith(exts) {
  return b.sequence([b.sequence([
    b.integer(1n), ALG, ISSUER,
    utc("2026-01-01T00:00:00Z"), utc("2026-02-01T00:00:00Z"),
    b.explicit(0, b.sequence(exts)),
  ]), ALG, SIG]);
}
var AKI = ext("authorityKeyIdentifier", false, b.sequence([b.contextPrimitive(0, Buffer.alloc(20, 7))]));
var BASE = crlWith([ext("cRLNumber", false, b.integer(1n)), AKI]);

function lintNeverThrows(input) {
  var report = pki.lint.crl(input);
  if (!report || !Array.isArray(report.findings) || !report.counts) {
    throw new Error("lint.crl returned a malformed report");
  }
}

module.exports.fuzz = function (data) {
  // (1) raw bytes -> the ingestion never-throw boundary.
  lintNeverThrows(data);

  // (2) splice onto a real CRL so the rules run on hostile decoded values.
  if (data.length >= 2) {
    var der = Buffer.from(BASE);
    var start = Math.max(0, der.length - data.length);
    data.copy(der, start, 0, Math.min(data.length, der.length - start));
    lintNeverThrows(der);
  }

  // (3) the bytes AS a recognized extension value, which is the path the rules that
  // decode a value take. Every extension the CRL profile reads a value out of appears
  // here, so a rule that decodes one is driven on attacker-controlled bytes:
  // issuingDistributionPoint and freshestCRL go through the same readers certification
  // path validation and the certificate profile use, so those readers are driven too.
  if (data.length >= 1 && data.length <= 4096) {
    var withIdp;
    try {
      withIdp = crlWith([
        ext("cRLNumber", false, b.integer(1n)), AKI,
        ext("issuingDistributionPoint", true, data),
        ext("deltaCRLIndicator", true, data),
        ext("authorityInfoAccess", false, data),
        ext("freshestCRL", false, data),
      ]);
    } catch (_e) {
      // The BUILDER refusing these bytes is not the contract under test; only the
      // linter's never-throw promise is, and there is nothing to drive it with here.
      return;
    }
    lintNeverThrows(withIdp);
  }
};
