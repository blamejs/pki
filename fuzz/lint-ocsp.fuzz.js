// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: OCSP response linting via pki.lint.ocsp.
 *
 * libFuzzer / jazzer.js harness. The linter is the one toolkit surface whose DATA
 * path must NEVER throw: it surveys a corpus that includes malformed members, so a
 * hostile / truncated / non-DER input must return a LintReport (a `fatal`
 * lint/unparseable finding) rather than raise. This target drives three paths with the
 * fuzzer's bytes: (1) the raw bytes straight into lint.ocsp (exercises the never-throw
 * ingestion boundary), (2) the bytes spliced over the tail of a real response so the
 * outer framing still parses and the RULE closures run on attacker-controlled decoded
 * structures, and (3) the bytes as the value of every extension the profile reads a
 * value out of, on both extension lists, which is where the rules that DECODE a value
 * run.
 *
 * Contract: lint.ocsp(bytes) has exactly ONE acceptable outcome -- it RETURNS a report.
 * Any throw at all (a PkiError the linter should have caught, a RangeError, a bare
 * TypeError, a hang) is an unguarded invariant break: rethrow so jazzer records the
 * reproducer. (LintError is config-time only and unreachable from a bytes input.)
 */

var pki = require("..");
var b = pki.asn1.build;
var oid = pki.oid;

// A basic response assembled here rather than taken from a fixture, because the
// signature is never verified by linting and the builders are synchronous. The outer
// framing keeps the fuzzer's bytes reaching the rule closures after a splice.
var ALG = b.sequence([b.oid(oid.byName("ecdsaWithSHA256"))]);
var SIG = b.bitString(Buffer.alloc(8, 1), 0);
var DN = b.sequence([b.set([b.sequence([b.oid(oid.byName("commonName")), b.utf8("Fuzz Responder")])])]);
function gt(s) { return b.generalizedTime(new Date(s)); }
function ext(name, critical, inner) {
  var kids = [b.oid(oid.byName(name))];
  if (critical) kids.push(b.boolean(true));
  kids.push(b.octetString(inner));
  return b.sequence(kids);
}
var CERT_ID = b.sequence([b.sequence([b.oid(oid.byName("sha256")), b.nullValue()]), b.octetString(Buffer.alloc(32, 3)), b.octetString(Buffer.alloc(32, 4)), b.integer(1n)]);
function single(singleExts) {
  var kids = [CERT_ID, b.contextPrimitive(0, Buffer.alloc(0)), gt("2027-01-01T00:00:00Z"), b.explicit(0, gt("2028-01-01T00:00:00Z"))];
  if (singleExts) kids.push(b.explicit(1, b.sequence(singleExts)));
  return b.sequence(kids);
}
function responseWith(responseExts, singleExts) {
  var rd = [b.explicit(1, DN), gt("2027-01-01T00:00:00Z"), b.sequence([single(singleExts)])];
  if (responseExts) rd.push(b.explicit(1, b.sequence(responseExts)));
  var basic = b.sequence([b.sequence(rd), ALG, SIG]);
  return b.sequence([b.enumerated(0n), b.explicit(0, b.sequence([b.oid(oid.byName("ocspBasic")), b.octetString(basic)]))]);
}
var BASE = responseWith(null, null);

function lintNeverThrows(input) {
  var report = pki.lint.ocsp(input);
  if (!report || !Array.isArray(report.findings) || !report.counts) {
    throw new Error("lint.ocsp returned a malformed report");
  }
}

module.exports.fuzz = function (data) {
  // (1) raw bytes -> the ingestion never-throw boundary.
  lintNeverThrows(data);

  // (2) splice onto a real response so the rules run on hostile decoded values.
  if (data.length >= 2) {
    var der = Buffer.from(BASE);
    var start = Math.max(0, der.length - data.length);
    data.copy(der, start, 0, Math.min(data.length, der.length - start));
    lintNeverThrows(der);
  }

  // (3) the bytes AS one recognized extension value at a time, which is the path the
  // rules that decode a value take: the extended revoked definition on the response
  // list, and the CRL entry extensions the profile reads through the CRL parser's own
  // reader on the single list. ONE fuzzed extension per response, since the parser
  // refuses a malformed nonce, archive cutoff or CRL reference before any rule runs, so
  // a response carrying the same bytes in every extension never reaches the readers.
  // Those three parser-owned extensions are driven on their own too, since a value the
  // parser refuses must arrive as the fatal finding and never as a throw.
  if (data.length >= 1 && data.length <= 4096) {
    FUZZED_SLOTS.forEach(function (slot) {
      var one;
      try {
        one = slot.response ? responseWith([ext(slot.name, slot.critical, data)], null)
          : responseWith(null, [ext(slot.name, slot.critical, data)]);
      } catch (_e) {
        // The BUILDER refusing these bytes is not the contract under test; only the
        // linter's never-throw promise is, and there is nothing to drive it with here.
        return;
      }
      lintNeverThrows(one);
    });
  }
};

var FUZZED_SLOTS = [
  { name: "ocspExtendedRevoke", critical: false, response: true },
  { name: "ocspNonce", critical: false, response: true },
  { name: "reasonCode", critical: false, response: false },
  { name: "invalidityDate", critical: false, response: false },
  { name: "certificateIssuer", critical: true, response: false },
  { name: "ocspArchiveCutoff", critical: false, response: false },
  { name: "ocspCrl", critical: false, response: false },
];
