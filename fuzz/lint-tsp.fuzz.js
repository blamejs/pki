// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: timestamp token linting via pki.lint.tsp.
 *
 * libFuzzer / jazzer.js harness. The linter's DATA path must NEVER throw: a hostile,
 * truncated or non-DER input must return a LintReport (a `fatal` lint/unparseable
 * finding) rather than raise. This target drives the raw bytes into lint.tsp, which is
 * the ingestion boundary, and then splices them over the tail of a token so the outer
 * framing still parses and the rule closures run on attacker-controlled values. The rule
 * that reads the tsa hint parses a certificate out of the token, so hostile bytes reach a
 * second parser through it.
 *
 * Contract: lint.tsp(bytes) has exactly ONE acceptable outcome, it RETURNS a report. Any
 * throw at all is an unguarded invariant break: rethrow so jazzer records the reproducer.
 */

var pki = require("..");
var b = pki.asn1.build;
var oid = pki.oid;

var DIGEST_ALG = b.sequence([b.oid(oid.byName("sha256")), b.nullValue()]);
var SIG_ALG = b.sequence([b.oid(oid.byName("ecdsaWithSHA256"))]);
var DN = b.sequence([b.set([b.sequence([b.oid(oid.byName("commonName")), b.utf8("Fuzz TSA")])])]);

// The token carries ONE certificate, because the rule that reads the tsa hint applies only to a
// token that does: without it the fuzzed hint never reaches the certificate parser or the
// GeneralName comparisons, which is the path this harness exists to drive. The signature is never
// verified by linting, so the certificate is assembled here rather than signed.
var CERT_ALG = b.sequence([b.oid(oid.byName("Ed25519"))]);
var CERT_SAN = b.sequence([b.oid(oid.byName("subjectAltName")),
  b.octetString(b.sequence([b.contextPrimitive(2, Buffer.from("tsa.example"))]))]);
var TSA_CERT = b.sequence([
  b.sequence([
    b.explicit(0, b.integer(2n)), b.integer(1n), CERT_ALG, DN,
    b.sequence([b.utcTime(new Date("2026-01-01T00:00:00Z")),
      b.utcTime(new Date("2036-01-01T00:00:00Z"))]),
    DN,
    b.sequence([CERT_ALG, b.bitString(Buffer.alloc(32, 1), 0)]),
    b.explicit(3, b.sequence([CERT_SAN])),
  ]),
  CERT_ALG, b.bitString(Buffer.alloc(64, 2), 0),
]);

function tstInfo(tail) {
  var kids = [
    b.integer(1n),
    b.oid("1.2.3.4"),
    b.sequence([DIGEST_ALG, b.octetString(Buffer.alloc(32, 5))]),
    b.integer(1n),
    b.generalizedTime(new Date("2027-01-01T00:00:00Z")),
  ];
  if (tail) kids.push(tail);
  return b.sequence(kids);
}
function attr(name, value) {
  return b.sequence([b.oid(oid.byName(name)), b.setOf([value])]);
}
function tokenWith(tail) {
  var content = b.octetString(tstInfo(tail));
  var attrs = [
    attr("contentType", b.oid(oid.byName("tSTInfo"))),
    attr("messageDigest", b.octetString(Buffer.alloc(32, 9))),
    attr("signingCertificateV2", b.sequence([b.sequence([
      b.sequence([b.octetString(Buffer.alloc(32, 4))])])])),
  ];
  // The sid names the certificate above by its issuer and serial, so the rule that reads the tsa
  // hint can resolve it. A serial that does not match leaves the rule unreachable and the hint
  // path fuzzing nothing, which is what the assertion below refuses to let happen quietly.
  var signerInfo = b.sequence([
    b.integer(1n),
    b.sequence([DN, b.integer(1n)]),
    b.sequence([b.oid(oid.byName("sha256"))]),
    b.implicit(0, b.setOf(attrs), true),
    SIG_ALG,
    b.octetString(Buffer.alloc(16, 2)),
  ]);
  var signedData = b.sequence([
    b.integer(3n),
    b.setOf([b.sequence([b.oid(oid.byName("sha256"))])]),
    b.sequence([b.oid(oid.byName("tSTInfo")), b.explicit(0, content)]),
    b.implicit(0, b.setOf([TSA_CERT]), true),
    b.setOf([signerInfo]),
  ]);
  return b.sequence([b.oid(oid.byName("signedData")), b.explicit(0, signedData)]);
}
var BASE = tokenWith(null);

// The hint path is only worth fuzzing if it REACHES the rule that reads a hint, which needs the
// SignerInfo's identifier to resolve to the certificate above. Assert that here rather than trust
// it: a fixture that stopped reaching the rule would otherwise fuzz nothing and still report clean.
(function assertHintPathReachesTheRule() {
  var mismatching = tokenWith(b.explicit(0, b.contextPrimitive(2, Buffer.from("elsewhere.example"))));
  var matching = tokenWith(b.explicit(0, b.contextPrimitive(2, Buffer.from("tsa.example"))));
  var reported = pki.lint.tsp(mismatching).findings.some(function (f) {
    return f.id === "lint/rfc3161/tsa-name-mismatch";
  });
  var quiet = pki.lint.tsp(matching).findings.every(function (f) {
    return f.id !== "lint/rfc3161/tsa-name-mismatch";
  });
  if (!reported || !quiet) {
    throw new Error("lint-tsp fuzz fixture does not reach tsa-name-mismatch in both directions");
  }
})();

function lintNeverThrows(input) {
  var report = pki.lint.tsp(input);
  if (!report || !Array.isArray(report.findings) || !report.counts) {
    throw new Error("lint.tsp returned a malformed report");
  }
}

module.exports.fuzz = function (data) {
  // (1) raw bytes -> the ingestion never-throw boundary.
  lintNeverThrows(data);

  // (2) splice onto a real token so the rules run on hostile decoded values.
  if (data.length >= 2) {
    var der = Buffer.from(BASE);
    var start = Math.max(0, der.length - data.length);
    data.copy(der, start, 0, Math.min(data.length, der.length - start));
    lintNeverThrows(der);
  }

  // (3) the bytes AS the tsa hint, which is the field the profile reads a GeneralName out
  // of and then compares against a certificate it parses itself.
  if (data.length >= 1 && data.length <= 4096) {
    var one;
    try { one = tokenWith(b.explicit(0, b.raw(data))); }
    catch (_e) {
      // The BUILDER refusing these bytes is not the contract under test.
      return;
    }
    lintNeverThrows(one);
  }
};
