// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.schema.trustanchor.parse / parseInfo
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite (CI PRs + nightly batch)
 * and OSS-Fuzz (continuous) both consume this shape:
 * `module.exports.fuzz = function (data)` where `data` is a Buffer the
 * engine mutates via coverage-guided fuzzing.
 *
 * RFC 5914's two tagged structures both number their members with a GAP:
 * TrustAnchorInfo has no [0], its `exts` is [1] EXPLICIT and its language
 * tag [2]; TrustAnchorChoice has no [0] either, its `tbsCert` is [1] and its
 * `taInfo` [2], with `certificate` untagged. The mutator reaches those tag
 * boundaries, the three-way CHOICE dispatch, the embedded Certificate and
 * TBSCertificate walks, the CertPathControls [0]..[4] run, and the
 * certificate-to-anchor matching rules that compare a decoded subject, public
 * key and key identifier against the anchor's own.
 *
 * Both doors are driven, since `parseInfo` reads the inner structure with no
 * list around it and so reaches the TrustAnchorInfo walk on inputs the list
 * parser rejects at its first element.
 *
 * Contract: parsing attacker-controlled bytes has exactly two acceptable
 * outcomes -- a successful parse, or a thrown `pki.errors.PkiError`
 * (TrustAnchorError / CertificateError / Asn1Error / OidError / PemError).
 * Any other throw (a RangeError, a stack overflow from the nested walk, a bare
 * TypeError, a hang) means the parser surfaced an unguarded invariant break on
 * hostile input: rethrow it so jazzer records the reproducer.
 */

var pki = require("..");

var DOORS = [pki.schema.trustanchor.parse, pki.schema.trustanchor.parseInfo];

module.exports.fuzz = function (data) {
  for (var i = 0; i < DOORS.length; i++) {
    try {
      DOORS[i](data);
    } catch (e) {
      if (e instanceof pki.errors.PkiError) continue;
      throw e;
    }
  }
};
