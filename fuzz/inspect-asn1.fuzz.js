// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.inspect.asn1
 *
 * Runs under libFuzzer via jazzer.js. The structural dump is the one renderer that
 * reads hostile bytes itself: when pki.asn1.decode refuses the input, a tolerant
 * header-by-header walk inside the renderer reads the tag and length octets. That
 * walk is a second reader of DER headers, so it is the code this target exists to
 * drive, and every seed that the strict decoder rejects reaches it.
 *
 * Contract: rendering attacker-controlled bytes may only RETURN a string or THROW a
 * pki.errors.PkiError (InspectError -- inspect/bad-input -- or a PemError from the
 * armor probe). Any other throw is a finding: a RangeError or a raw TypeError means
 * the walk dereferenced past a bound, and a stack overflow means the depth cap did
 * not hold. A hang means a length or an offset advanced by zero somewhere, which is
 * the one way a header walk can loop.
 *
 * The caps are driven too. A run with a small maxNodes and maxValueBytes exercises
 * the stop-at-the-cap paths that the default caps reach only on a large input, and a
 * small maxDepth pushes every seed through the walk rather than the strict decode.
 */
var pki = require("..");

function drive(input, opts) {
  try {
    var out = opts === undefined ? pki.inspect.asn1(input) : pki.inspect.asn1(input, opts);
    if (typeof out !== "string") throw new Error("inspect.asn1 returned a non-string");
  } catch (e) {
    if (!(e instanceof pki.errors.PkiError)) throw e;
  }
}

module.exports.fuzz = function (data) {
  drive(data);
  // The same bytes as a string drive the PEM armor probe and the base64 decode.
  drive(data.toString("latin1"));
  // Small caps reach the stop-at-the-cap paths; a maxDepth of 1 forces the walk.
  drive(data, { maxNodes: 4, maxValueBytes: 2 });
  drive(data, { maxDepth: 1 });
};
