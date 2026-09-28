// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: CMS message linting via pki.lint.cms.
 *
 * libFuzzer / jazzer.js harness. The linter is the one toolkit surface whose DATA path
 * must NEVER throw: it surveys a corpus that includes malformed members, so a hostile,
 * truncated or non-DER input must return a LintReport (a `fatal` lint/unparseable
 * finding) rather than raise. This target drives three paths with the fuzzer's bytes:
 * (1) the raw bytes straight into lint.cms, which is the ingestion boundary, (2) the
 * bytes spliced over the tail of a real SignedData so the outer framing still parses and
 * the RULE closures run on attacker-controlled decoded structures, and (3) the bytes as
 * the value of each signed attribute the profile reads, which is the path the rule that
 * decodes a signing-time takes.
 *
 * Contract: lint.cms(bytes) has exactly ONE acceptable outcome, it RETURNS a report. Any
 * throw at all is an unguarded invariant break: rethrow so jazzer records the reproducer.
 */

var pki = require("..");
var b = pki.asn1.build;
var oid = pki.oid;

// A SignedData assembled here rather than taken from a fixture, because linting never
// verifies the signature and the builders are synchronous.
var DIGEST_ALG = b.sequence([b.oid(oid.byName("sha256"))]);
var SIG_ALG = b.sequence([b.oid(oid.byName("ecdsaWithSHA256"))]);
var DN = b.sequence([b.set([b.sequence([b.oid(oid.byName("commonName")), b.utf8("Fuzz Signer")])])]);
var CONTENT = Buffer.from("fuzz content");

function attr(name, value) {
  return b.sequence([b.oid(oid.byName(name)), b.setOf([value])]);
}
function signedDataWith(extraAttrs) {
  var attrs = [
    attr("contentType", b.oid(oid.byName("data"))),
    attr("messageDigest", b.octetString(Buffer.alloc(32, 9))),
  ].concat(extraAttrs || []);
  var signerInfo = b.sequence([
    b.integer(1n),
    b.sequence([DN, b.integer(7n)]),
    DIGEST_ALG,
    b.implicit(0, b.setOf(attrs), true),
    SIG_ALG,
    b.octetString(Buffer.alloc(16, 2)),
  ]);
  var signedData = b.sequence([
    b.integer(1n),
    b.setOf([DIGEST_ALG]),
    b.sequence([b.oid(oid.byName("data")), b.explicit(0, b.octetString(CONTENT))]),
    b.setOf([signerInfo]),
  ]);
  return b.sequence([b.oid(oid.byName("signedData")), b.explicit(0, signedData)]);
}
var BASE = signedDataWith(null);

function lintNeverThrows(input) {
  var report = pki.lint.cms(input);
  if (!report || !Array.isArray(report.findings) || !report.counts) {
    throw new Error("lint.cms returned a malformed report");
  }
}

// The signed attributes whose values a rule reads. A signing-time is the one the profile
// decodes; the other two are the ones the PARSER decodes, and a value it refuses must
// arrive as the fatal finding rather than as a throw.
var FUZZED_ATTRS = ["signingTime", "contentType", "messageDigest"];

module.exports.fuzz = function (data) {
  // (1) raw bytes -> the ingestion never-throw boundary.
  lintNeverThrows(data);

  // (2) splice onto a real message so the rules run on hostile decoded values.
  if (data.length >= 2) {
    var der = Buffer.from(BASE);
    var start = Math.max(0, der.length - data.length);
    data.copy(der, start, 0, Math.min(data.length, der.length - start));
    lintNeverThrows(der);
  }

  // (3) the bytes AS one signed attribute value at a time. One fuzzed attribute per
  // message, since the parser refuses a malformed content-type or message-digest before
  // any rule runs and a message carrying the bytes in every slot never reaches the rest.
  if (data.length >= 1 && data.length <= 4096) {
    FUZZED_ATTRS.forEach(function (name) {
      var one;
      try { one = signedDataWith([attr(name, b.raw(data))]); }
      catch (_e) {
        // The BUILDER refusing these bytes is not the contract under test.
        return;
      }
      lintNeverThrows(one);
    });
  }
};
